import json

from config import ConfigReader
from src import utils
import dataset
from typing import List, Union
from datetime import datetime, timezone, timedelta

logger = utils.Logger()
config = ConfigReader()


def get_vuln_all(modified_start: datetime | None = None, *args, **kwargs):
    url = config.get("VULN.jsonapi")
    params = kwargs

    if modified_start is not None:
        params["lastModStartDate"] = modified_start.isoformat()
        params["lastModEndDate"] = datetime.now(timezone.utc).isoformat()

    vuln_all = []
    total = 100
    while len(vuln_all) < total:
        params["startIndex"] = len(vuln_all)
        response = utils.requests_url(url=url, params=params).json()
        vuln_all.extend(response['vulnerabilities'])
        total = response['totalResults']

    return vuln_all


class CVEVuln:
    def __init__(self):
        self.vulns = None

    def information_extraction(self, range: str | int | datetime = 'm', *args, **kwargs):
        """
        漏洞信息提取
        :return:
        """
        if isinstance(range, int):
            current_date = datetime.now()
            start_date = current_date - timedelta(days=range)
        elif isinstance(range, datetime):
            start_date = range
        else:
            if range == 'd':
                start_date = datetime.now().replace(hour=0)
            elif range == 'm':
                start_date = datetime.now().replace(day=1, hour=0)
            elif range == 'y':
                start_date = datetime.now().replace(month=1, day=1, hour=0)
            else:
                start_date = None

        vuln_all = get_vuln_all(start_date, *args, **kwargs)
        vuln_dict = {}
        for vuln in vuln_all:
            vuln_dict[vuln['cve']['id']] = VulnInfo(vuln['cve'])

        self.vulns = vuln_dict
        return self.vulns


class VulnInfo:
    def __init__(self, cve):
        self.cve = cve

    @property
    def cve_id(self):
        return self.cve['id']

    @property
    def name(self):
        return None

    @property
    def cnvd_id(self):
        return None

    @property
    def cnnvd_id(self):
        return None

    @property
    def create_date(self):
        """
        创建时间
        :return:
        """
        return self.cve['published'].split('T')[0]

    @property
    def updated_date(self):
        """
        更新时间
        :return:
        """
        return self.cve['lastModified'].split('T')[0]

    @property
    def discovery_date(self):
        """
        发现时间
        :return:
        """
        return self.create_date

    @property
    def disclosure_date(self):
        """
        公布时间
        :return:
        """
        return self.create_date

    @property
    def start(self):
        return self.cve.get("vulnStatus", None)

    @property
    def description(self):
        for desc in self.cve["descriptions"]:
            if desc["lang"] == "en":
                return desc["value"]
        return None

    @property
    def affected_versions(self):
        """
        cpe:2.3:a:mozilla:firefox:3.5:*:*:*:*:*:*:*
        CPE 2.3标准 ： 产品类型： 厂商名称： 产品名称： 版本号： 补丁版本： 产品变体： 语言版本： 软件变体： 目标平台： 其他属性： 可选属性
        :return:
        """
        versions = []
        for nodes in self.cve.get("configurations", list()):
            for node in nodes['nodes']:
                for cpe in node['cpeMatch']:
                    versions.append(cpe.get('criteria'))

        return list(set(versions))

    @property
    def type(self):
        types = []
        for weak in self.cve.get("weaknesses", list()):
            for desc in weak["description"]:
                if desc['lang'] == 'en':
                    types.append(desc['value'])

        return types

    @property
    def cvss(self):
        """
        cvss 评分及严重等级
        :return: {版本名称：{评分， 等级}}
        """
        cvss = dict()
        for cvss_name, values in self.cve.get("metrics", dict()).items():
            for value in values:
                if value['type'] == "Primary":
                    if "baseSeverity" in value.keys():
                        cvss["severity"] = value["baseSeverity"]
                    else:
                        cvss["severity"] = value['cvssData']["baseSeverity"]
                    cvss["score"] = value['cvssData']["baseScore"]
        return cvss

    @property
    def attack(self):
        return None

    @property
    def solution(self):
        """
        修复方案
        :return:
        """
        solution_all = []
        for ref in self.cve.get("references", list()):
            solution_all.append(ref["url"])
        return solution_all

    def info(self):
        """返回所有property属性生成的字典"""
        props = {}
        for attr_name in dir(self):
            if attr_name.startswith('_') or attr_name in ("cve", "info"):
                continue
            props[attr_name] = getattr(self, attr_name)
        return props


def save_mysql(data: Union[VulnInfo, List[VulnInfo]], keys=None):
    """
    将漏洞数据保存到数据库中
    :return:
    """
    cof = config.get('MYSQL')
    url = f"mysql://{cof.get('user')}:{cof.get('password')}@{cof.get('host')}/{cof.get('database')}"
    db = dataset.connect(url=url)
    table = db.load_table('vuln_info')
    if not table.exists:
        logger.error(f"Not table {cof.get('database')}.vuln_info")
        return None
    save_json = []
    if not isinstance(data, list):
        data = [data]

    logger.info(f'cve num: {len(data)}')
    for i, vuln in enumerate(data):
        info = vuln.info()
        if table.count(cve_id=info.get('cve_id')):
            logger.info(f"{info.get('cve_id')} is exists")
            continue
        insert_json = {}
        for key, value in info.items():
            if key == 'cvss':
                insert_json['cvss_score'] = value.get('score')
                insert_json['severity'] = value.get('severity')
                continue
            elif key == 'type':
                column = 'vuln_type'
            elif key == 'name':
                column = 'vuln_name'
            else:
                column = key

            if isinstance(value, list):
                insert_json[column] = ' \r\n'.join(value)
            else:
                insert_json[column] = value

        save_json.append(insert_json)
        if len(save_json) >= 100 or i == len(data) - 1:
            logger.info(f"save data num: {len(save_json)}")
            if keys:
                table.upsert_many(save_json, keys)
            else:
                table.insert_many(save_json)
            save_json.clear()
    db.close()


if __name__ == '__main__':
    # from pathlib import Path
    # import os
    # from tqdm import tqdm
    #
    # vuln_path = Path(r"E:\kali_python\furate-cve\data\trickest\nvd-json-data-feeds")
    # vuln = CVEVuln()
    # for cve_y in vuln_path.iterdir():
    #     if not cve_y.name.startswith('CVE') or cve_y.name > 'CVE-2015':
    #         continue
    #     for cve_dir in cve_y.iterdir():
    #         if not cve_dir.name.startswith('CVE'):
    #             continue
    #         info_all = {}
    #         for json_file in tqdm(os.listdir(cve_dir), desc=cve_dir.name):
    #             if not json_file.endswith('.json'):
    #                 continue
    #             with open(cve_dir / json_file, 'r') as f:
    #                 info = json.load(f)
    #                 info_all[info['id']] = VulnInfo(info)
    #
    #         vuln.save_mysql(info_all)
    cve_vuln = CVEVuln()
    data = cve_vuln.information_extraction(resultsPerPage=1000)
    save_mysql(list(data.values()))

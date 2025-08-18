"""
获取国家信息漏洞库中的所有漏洞信息
CVE编号、cnnvd编号、漏洞名称、录入日期、更新日期、漏洞来源，严重等级、厂商、漏洞类型、楼顶描述
"""
import json
import os
import chardet
import requests
import time
from tqdm import tqdm
from bs4 import BeautifulSoup
from pathlib import Path

from src.utils import Logger

logger = Logger("CNNVD")



class CNNVDCrawler:
    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = 5
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            "content-type": "application/json;charset=UTF-8",
            "origin": "https://www.cnnvd.org.cn",
            "referer": "https://www.cnnvd.org.cn/home/globalSearch?keyword=",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        })

    @staticmethod
    def url(api=None):
        url = r"https://www.cnnvd.org.cn/"
        if api:
            return url + api
        else:
            return url

    @logger.log_duration
    def search_vendor(self, api="web/homePage/searchVendorList") -> dict:
        """
        获取厂商信息
        :param api: 接口地址
        :return:
        """
        data = {
            "pageIndex": 1,
            "pageSize": 100
        }
        response = self.session.post(url=self.url(api), data=json.dumps(data))
        response.raise_for_status()

        vendors = dict()
        for vendor in response.json()["data"]:
            vendors[vendor["id"]] = {
                "name": vendor["vendorName"],
                "name_en": vendor["vendorNameEn"],
                "vul_total": vendor["vulTotal"],
            }
        return vendors

    @logger.log_duration
    def cnnvd_vuln(self, api="web/homePage/cnnvdVulList") -> list:
        """
        获取 漏洞列表
        :param api: 接口地址
        :return:
        """
        page_size = 100
        data = {
            "pageIndex": 1,
            "pageSize": page_size,
            "keyword": ""
        }
        records = list()
        while True:
            response = self.session.post(url=self.url(api), data=json.dumps(data))
            response.raise_for_status()

            response_data = response.json()["data"]
            records.extend(response_data["records"])
            if len(response_data["records"]) < page_size:
                break
            time.sleep(2)

        return records

    def vuln_detail(self, api="web/cnnvdVul/getCnnnvdDetailOnDatasource"):
        """
        获取每个漏洞的详情信息
        :param api:
        :return:
        """
        vul_all = self.cnnvd_vuln()
        logger.info(f"CNNVD vul num : {len(vul_all)}")
        vuln_details = list()
        for vuln in tqdm(vul_all, desc="vul_detail"):
            data = {
                "id": vuln["id"],
                "vulType": vuln["vulType"],
                "cnnvdCode": vuln["cnnvdCode"]
            }
            response = self.session.post(url=self.url(api), data=json.dumps(data))
            response.raise_for_status()

            vuln_details.append(response.json()["data"])
            time.sleep(2)

        return vuln_details


class CNNVDXml:
    def __init__(self, xml_path):
        self.xml_path = Path(xml_path)

    def read_xml(self) -> [BeautifulSoup, Path]:
        for file in self.xml_path.iterdir():
            if not file.is_file() and file.suffix != ".xml":
                logger.debug(f"The file is not in XML format：{file}")
                continue
            logger.debug(f"Read XML file: {file}")
            with open(file, 'rb') as xf:
                raw_data = xf.read()
            encoding = chardet.detect(raw_data)['encoding']
            vuln_data = BeautifulSoup(raw_data, "xml", from_encoding=encoding)

            yield vuln_data, file

    def data_analysis(self):
        xml_file = self.read_xml()
        vul_all = []
        for data, file_path in tqdm(xml_file, desc="analysis", total=len(os.listdir(self.xml_path))):
            file_vuln = data.findAll("entry")
            for vuln in file_vuln:
                vuln_info = {
                    "vuln_name": vuln.find("name").text,  # 漏洞名称
                    "cnnvd_id": vuln.find("vuln-id").text,  # cnnvd 编号
                    "release_time": vuln.find("published").text,  # 发布时间
                    "update_time": vuln.find("modified").text,  # 更新时间
                    "publishing_unit": vuln.find("source").text,  # 发布单位
                    "hazard_level": vuln.find("severity").text,  # 危害等级
                    "vuln_type": vuln.find("vuln-type").text,  # 漏洞类别
                    "vuln_desc": vuln.find("vuln-descript").text,  # 漏洞描述
                }
                # 漏洞利用
                if vuln.find("vuln-exploit"):
                    vuln_info["vuln_exp"] = vuln.find("vuln-exploit").text

                # 实体描述信息，包含厂商、产品名称和版本号
                if vuln.find("vulnerable-configuration"):
                    entity_description = vuln.find("vulnerable-configuration")
                    for cncpe in entity_description.children:
                        logger.warning(f"There is a vulnerability-configuration attribute：{file_path}")
                        pass
                # 影响产品描述
                if vuln.find("vuln-software-list"):
                    logger.warning(f"There is a vuln-software-list attribute：{file_path}")
                    pass
                # 相关编号，包含CVE编号和bugtraq编号
                if vuln.find("other-id"):
                    vuln_id_list = vuln.find("other-id")
                    vuln_info["CVE_id"] = vuln_id_list.find("cve-id").text
                    vuln_info["bugtraq_id"] = vuln_id_list.find("bugtraq-id").text

                # 解决方案
                if vuln.find("vuln-solution"):
                    vuln_info["vuln_solution"] = vuln.find("vuln-solution").text

                # 参考网址 包含来源，名称，链接
                if vuln.find("vuln-solution"):
                    urls = vuln.find("vuln-solution")
                    vuln_info["source"] = []
                    for url in urls.children:
                        vuln_info["source"].append({
                            "source": url.find("ref-source").text,
                            "name": url.find("ref-name").text,
                            "url": url.find("ref-url").text,
                        })
                vul_all.append(vuln_info)
        return vul_all

    def save_mysql(self, data):
        """
        将数据保存到数据库中
        :param data:
        :return:
        """
        pass


if __name__ == '__main__':
    # crawler = CNNVDCrawler()
    # vulns = crawler.vul_detail()
    # print(len(vulns), "\n", vulns[0])

    xml_vuln = CNNVDXml(r"E:\kali_python\furate-cve\data\vul_cnnvd")
    xml_vuln.data_analysis()

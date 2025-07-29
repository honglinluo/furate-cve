"""
获取国家信息漏洞库中的所有漏洞信息
CVE编号、cnnvd编号、漏洞名称、录入日期、更新日期、漏洞来源，严重等级、厂商、漏洞类型、楼顶描述
"""
import json
import requests
import time
from tqdm import tqdm

from src.utils.logger import Logger

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
    def cnnvd_vul(self, api="web/homePage/cnnvdVulList") -> list:
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

    def vul_detail(self, api="web/cnnvdVul/getCnnnvdDetailOnDatasource"):
        """
        获取每个漏洞的详情信息
        :param api:
        :return:
        """
        vul_all = self.cnnvd_vul()
        logger.info(f"CNNVD vul num : {len(vul_all)}")
        vul_details = list()
        for vul in tqdm(vul_all, desc="vul_detail"):
            data = {
                "id": vul["id"],
                "vulType": vul["vulType"],
                "cnnvdCode": vul["cnnvdCode"]
            }
            response = self.session.post(url=self.url(api), data=json.dumps(data))
            response.raise_for_status()

            vul_details.append(response.json()["data"])
            time.sleep(2)

        return vul_details


if __name__ == '__main__':
    crawler = CNNVDCrawler()
    vuls = crawler.vul_detail()
    print(len(vuls), "\n", vuls[0])

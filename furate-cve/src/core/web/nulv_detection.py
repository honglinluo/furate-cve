from src.utils import Logger, requests_url, run as asyncio_run
from src.core.msf.msf_rpc_client import MsfClient
from src.core.web.web_fingerprint import WebFingerPrinter
from config.config_read import ConfigReader
from typing import List
import asyncio

logger = Logger(level="INFO")


class Detection:
    def __init__(self, url, *args, **kwargs):
        # self.response = requests_url(url=url, method=kwargs.get("method", "get"), **kwargs)
        self.response = asyncio_run(url=url)
        self.web_fp = WebFingerPrinter()
        self.config = ConfigReader()
        # self.msf = MsfClient(self.config.get("client_info"))

    def finger_printer(self):
        """
        对网站进行指纹识别，并返回指纹信息
        :return:  {'jQuery': {'versions': ['1'], 'categories': ['JavaScript libraries']}}
        """
        result = self.web_fp.analyze(self.response)

        logger.info(f"Total number of technology stacks: {self.web_fp.get_tech_count(result)}")
        logger.debug(f"technology stacks: {self.web_fp.format_result(result)}")
        return result

    def msf_auxiliary(self, technical) -> List[dict]:
        """
        在msf中查询该技术的复制模块
        :param technical:需要差尊的技术类型
        :return: [模块全名:{模块名称，……}]
        """
        result = self.msf.search(technical)
        if result:
            logger.info(f"Query the MSF auxiliary moduls: {len(result['auxiliary'])} ")
            model_all = []
            for model in result["auxiliary"]:
                full_name = model.get("fullname")
                model_all.append({
                    full_name: model
                })
            logger.debug("MSF auxiliary moduls: {model_all}")
            return model_all
        else:
            logger.warning(f"The corresponding auxiliary moduls is not queried in MSF:{technical}")

    def run(self):
        stack = self.finger_printer()
        # for k, v in stack.items():
        #     auxiliary = self.msf_auxiliary(k)
        #     print(auxiliary)


if __name__ == '__main__':
    l = "https://91a2c0front-wc.jandemetal.com/cdn/91a2c0FNEW/_wms/static/_l/_data/_promo/promo.txt?1754213590725="
    d = Detection(l)
    d.run()

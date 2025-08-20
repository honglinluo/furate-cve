"""
1、创建一个浏览器，模拟用户对网页进行查看
2、监听网页运行时的所有接口，然后对接口进行指纹判定
3、页面html解析，解析所有的链接
4、对当前页面及跳转页面进行漏洞搜索，如文件上传、sql注入、XXE等漏洞验证
5、对服务器端口进行扫描
"""
from src.core.web.fingerprint import WebFingerPrinter
from src.utils import *
from config.config_read import ConfigReader
from DrissionPage._units.listener import DataPacket, Response
from DrissionPage import Chromium, ChromiumOptions
from typing import List, Dict, Literal, Union, Iterable, Tuple
from DrissionPage.items import MixTab
from collections import defaultdict
from tqdm import tqdm
import requests

logger = Logger(level="INFO")


class Web:
    __RES_TYPE__ = Literal['Document', 'Stylesheet', 'Image', 'Media', 'Font', 'Script', 'TextTrack', 'XHR', 'Fetch',
    'Prefetch', 'EventSource', 'WebSocket', 'Manifest', 'SignedExchange', 'Ping', 'CSPViolationReport',
    'Preflight', 'Other']

    def __init__(self, url):
        self.url = url
        self.web = self._chrome_strat()
        self.conf = ConfigReader()
        self.web_fp = WebFingerPrinter()

    @staticmethod
    def _chrome_strat():
        """
        创建浏览器对象，并对浏览器对象化进行设置
        :return:
        """
        co = ChromiumOptions()
        # co.no_imgs(True) # 无图片模式
        # co.mute(True) # 无声音
        return Chromium(addr_or_opts=co)

    def create_table(
            self,
            urls: Union[str, list, None] = None,
            is_latest_tab: bool = True
    ) -> Dict[any, dict]:
        """
        创建table页面，并打开url链接
        :param urls: 需要打开的url链接
        :param is_latest_tab: 是否在当前页面打开
        :return: {url:table}
        """
        if urls is None:
            urls = [self.url]
        if isinstance(urls, str):
            urls = [urls]

        url_tables = defaultdict(dict)
        if is_latest_tab:
            # 在当前页面打开链接
            table = self.web.latest_tab
            c_url = urls.pop(0)
            packets, tech_stack = self.listen_table(table, c_url)
            url_tables[c_url]["table"] = table.tab_id
            url_tables[c_url]["packet"] = packets
            requests.get(url=c_url, )
        for url in urls:
            table = self.web.new_tab()
            packets, tech_stack = self.listen_table(table, url)
            url_tables[url]["table"] = table.tab_id
            url_tables[url]["packet"] = packets
        return url_tables

    def listen_table(
            self,
            table: MixTab,
            url: str,
            res_type: Union[__RES_TYPE__, list, tuple, set, bool, None] = None
    ) -> tuple[list[DataPacket | list[DataPacket]], dict[str, dict]]:
        """
        监听页面接口信息
        :param table: 用于请求url的页面
        :param url: 需要请求的url地址
        :param res_type: 监听接口响应类型
        :return: [[当前页面的接口信息], 当前页面的技术栈]
        """
        if res_type is None:
            res_type = self.conf.get('WEB.ResType')
        packets_list = list()
        url_packet = None
        table.listen.start(res_type=res_type)
        table.get(url)
        logger.info(f"Open url:{table.tab_id} >> {url}")
        packets = table.listen.steps(timeout=int(self.conf.get("WEB.timeout", 5)))
        for packet in packets:
            packets_list.append(packet)
            logger.debug(f"Listen API: {packet.url}")
            if packet.url == url:
                url_packet = packet
        table.listen.stop()
        logger.info(f"Listen table API num: {len(packets_list)}")
        tech_stack = self.fingerprint(url=url, headers=url_packet.request.headers)
        return packets_list, tech_stack

    def fingerprint(self, url: str = None, response: requests.Response = None, *args, **kwargs) -> Dict[str, dict]:
        """
        根据url获取网站的技术栈
        :param response: 响应数据
        :param url: 请求地址
        :return: {'Windows Server': {'versions': [], 'categories': [
        'Operating systems']}, 'Microsoft ASP.NET': {'versions': [], 'categories': ['Web frameworks']},
        'IIS': {'versions': ['10.0'], 'categories': ['Web servers']}}
        """
        logger.info("Get the tech stack...")
        if url and response is None:
            response = requests.get(url=url, verify=True, *args, **kwargs)
        result = self.web_fp.analyze_response(response)
        logger.info(f"Number of tech stacks: {len(result)}")
        return result

    def table_info(self, table: MixTab = None):
        """
        对页面内容进行解析
        :param table:
        :return:
        """
        pass


class TableParse:
    def __init__(self, table: MixTab):
        """
        对页面进行解析，并判断是否有相关漏洞
        :param table:
        """
        self.table = table


class APIParse:
    __packet_type__ = ['Script']

    def __init__(self, packets: Union[DataPacket, List[DataPacket]]):
        """
        对接口信息进行解析，判断请求信息中是否包含XXE，是否可以sql注入，一级接口响应进行指纹识别
        :param packets: 接口列表
        """
        self.packets = packets if isinstance(packets, list) else [packets]

    def analyse(self):
        """
        对接口进行分析，主要分析请求url以及请求内容
        :return:
        """
        for packet in self.packets:
            if packet.resourceType not in self.__packet_type__:
                continue

            if packet.method in ["Post", "Put"]:
                # 对rul进行xxe等分析
                post_data = packet.request.postData
            else:
                params = packet.request.params
                # 对url进行sql注入验证
                if params:
                    pass


if __name__ == '__main__':
    u = "https://drissionpage.cn/browser_control/browser_object/"
    web = Web(url=u)
    web.create_table()

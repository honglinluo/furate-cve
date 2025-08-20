import requests
from Wappalyzer import Wappalyzer, WebPage
from typing import Dict, Optional
from src.utils import Logger

logger = Logger()

class WebFingerPrinter:
    def __init__(self):
        """
        初始化指纹检测器
        """
        self.wappalyzer = Wappalyzer.latest()

    def analyze_response(self, response) -> Dict[str, Dict]:
        """
        分析响应数据中的技术栈
        :param response: 网站的相应数据
        :return: 技术栈字典 {技术类别: {技术名称: 版本}}
        """
        try:
            web = WebPage.new_from_response(response)
            return self.wappalyzer.analyze_with_versions_and_categories(web)
        except Exception as e:
            logger.error(f"分析失败: {str(e)}")
            return {}

    def analyze_url(self, url:str, *args, **kwargs):
        """
        访问url地址，分析网站技术栈
        :param url:
        :return:
        """
        try:
            web = WebPage.new_from_url(url=url, *args, **kwargs)
            return self.wappalyzer.analyze(web)
        except Exception as e:
            logger.error(f"分析失败: {str(e)}")
            return {}


    def get_tech_count(self, result: Dict) -> int:
        """获取检测到的技术总数"""
        return sum(len(techs) for techs in result.values())

    def format_result(self, result: Dict) -> str:
        """格式化输出结果"""
        output = []
        for category, techs in result.items():
            output.append(f"\n【{category.upper()}】")
            for name, data in techs.items():
                version = data.get('version', 'unknown')
                output.append(f"- {name} (v{version})")
        return '\n'.join(output)


if __name__ == '__main__':
    # 使用示例
    # fingerprinter = WebFingerPrinter()
    target_url = "https://drissionpage.cn/browser_control/browser_object/"
    # tech_stack = fingerprinter.analyze(target_url)
    #
    # print(f"检测到 {fingerprinter.get_tech_count(tech_stack)} 项技术:")
    # print(fingerprinter.format_result(tech_stack))

    wappalyzer = Wappalyzer.latest()
    webpage = WebPage.new_from_url(target_url)
    results = wappalyzer.analyze(webpage)
    print(results)
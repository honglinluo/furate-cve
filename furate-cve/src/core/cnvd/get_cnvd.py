import requests
from bs4 import BeautifulSoup
import time
import random


class CNVDCrawler:
    def __init__(self):
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def _get_js_cookie(self, response_text):
        """解析JS生成__jsl_clearance cookie"""
        js_code = response_text.split('<script>')[1].split('</script>')
        if isinstance(js_code, list):
            js_code = js_code  # 取第一个元素
        js_code = str(js_code).replace('eval(', 'return(')
        ctx = execjs.compile(js_code)
        cookie_str = ctx.call('x')
        return {cookie_str.split('='): cookie_str.split('=')[1].split(';')}

    def crawl(self, url):
        # 第一次请求获取JS挑战
        first_res = self.session.get(url, headers=self.headers)
        if first_res.status_code == 521:
            # 解析JS获取cookie
            cookies = self._get_js_cookie(first_res.text)
            # 携带新cookie二次请求
            self.session.cookies.update(cookies)
            time.sleep(random.uniform(1, 3))  # 随机延迟
            second_res = self.session.get(url, headers=self.headers)
            return second_res
        return first_res

    def parse_vulnerabilities(self, html):
        """解析漏洞列表"""
        soup = BeautifulSoup(html, 'html.parser')
        # 具体解析逻辑...
        return []

if __name__ == '__main__':
    crawler = CNVDCrawler()
    response = crawler.crawl('https://www.cnvd.org.cn/flaw/list')
    if response.status_code == 200:
        data = crawler.parse_vulnerabilities(response.text)
        print(f"成功获取{len(data)}条漏洞数据")
    else:
        print(f"请求失败，状态码: {response.status_code}")
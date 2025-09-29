import requests
import urllib3
from src.utils.logger import Logger
import urllib.parse
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin

logger = Logger()


@logger.log_duration
def requests_url(url, method='get', *args, **kwargs):
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 " \
                 "Safari/537.36"

    if "headers" not in kwargs.keys():
        kwargs["headers"] = {"User-Agent": user_agent}
    elif "User-Agent" not in kwargs["headers"].keys():
        kwargs["headers"]["User-Agent"] = user_agent
    if 'timeout' not in kwargs.keys():
        kwargs['timeout'] = 3
    logger.info(f"{method}: {url}")

    rerequests_max_num = 3
    rerequests_num = 0
    response = None
    while True:
        rerequests_num += 1
        try:
            response = requests.request(url=url, method=method, *args, **kwargs)
        except requests.exceptions.Timeout as te:
            if rerequests_num <= rerequests_max_num:
                logger.warning(f"Request timeout, frerequests {rerequests_num}")
                continue
            else:
                raise ConnectionError(f"The request timed out 3 times.")
        except Exception as e:
            raise e

        break

    # debug requests info
    logger.debug(f"{response.request.path_url} requests headers: {response.request.headers}")
    if response.request.method in ["POST", "PUT"]:
        logger.debug(f"{response.request.path_url} {response.request.method} data: {response.request.body}")

    # debug response headers
    logger.debug(f"{response.request.path_url} response headers: {response.headers}")

    return response


async def requests_async(url, method='get', *args, **kwargs):
    pass





async def fetch(session, url):
    try:
        async with session.get(url) as resp:
            return await resp.text()
    except Exception as e:
        print(f"Failed to fetch {url}: {str(e)}")
        return None


def extract_resources(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    resources = set()

    # 提取JS/CSS/图片等静态资源
    for tag in soup.find_all(['script', 'link', 'img', 'iframe']):
        if tag.name == 'script' and tag.get('src'):
            resources.add(urljoin(base_url, tag['src']))
        elif tag.name == 'link' and tag.get('rel') == ['stylesheet']:
            resources.add(urljoin(base_url, tag['href']))
        elif tag.name == 'img' and tag.get('src'):
            resources.add(urljoin(base_url, tag['src']))
        elif tag.name == 'iframe' and tag.get('src'):
            resources.add(urljoin(base_url, tag['src']))

    return list(resources)


async def crawl_all(url):
    async with aiohttp.ClientSession() as session:
        # 1. 获取主页面
        html = await fetch(session, url)
        if not html:
            return []

        # 2. 提取依赖资源
        resources = extract_resources(html, url)

        # 3. 并发请求所有资源
        tasks = [fetch(session, res_url) for res_url in resources]
        results = await asyncio.gather(*tasks)

        return {
            'main_page': html,
            'resources': dict(zip(resources, results))
        }


def run(url):
    target_url = url
    result = asyncio.run(crawl_all(target_url))
    print(f"Fetched {len(result['resources'])} dependencies")


def build_url(host, port, path="", scheme="http"):
    """
    构建完整URL
    :param host: 主机地址(如'example.com')
    :param port: 端口号(如8080)
    :param path: URL路径(如'/api/v1')
    :param scheme: 协议类型(默认http)
    :return: 完整URL字符串
    """
    if not isinstance(port, int):
        port = int(port)

    netloc = f"{host}:{port}" if port not in [80, 443] else host
    return urllib.parse.urlunparse((
        scheme,
        netloc,
        path.lstrip('/'),
        '',
        '',
        ''
    ))


# if __name__ == "__main__":
#     target_url = "https://example.com"
#     result = asyncio.run(crawl_all(target_url))
#     print(f"Fetched {len(result['resources'])} dependencies")



# if __name__ == "__main__":
    # logger.info(f"run requests")
    # data = {
    #     'page_no': 1,
    #     'page_size': 20,
    #     'rating_flag': 'true'
    # }
    # # response_1 = requests_url("https://ti.qianxin.com/alpha-api/v2/vuln/vuln-list", 'post', data=data)
    # requests_1 = requests_url("http://www.baidu.com/", params={"wd": 1})
    # # print(response.text)

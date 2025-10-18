import random

import requests
import urllib3
from src.utils.logger import Logger
import urllib.parse
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from collections import Counter

logger = Logger()


@logger.log_duration
def requests_url(url, method='get', status=True, *args, **kwargs):
    """
    :param method: method for the new :class:`Request` object: ``GET``, ``OPTIONS``, ``HEAD``, ``POST``, ``PUT``, ``PATCH``, or ``DELETE``.
    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary, list of tuples or bytes to send
        in the query string for the :class:`Request`.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) A JSON serializable Python object to send in the body of the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
    :param cookies: (optional) Dict or CookieJar object to send with the :class:`Request`.
    :param files: (optional) Dictionary of ``'name': file-like-objects`` (or ``{'name': file-tuple}``) for multipart encoding upload.
        ``file-tuple`` can be a 2-tuple ``('filename', fileobj)``, 3-tuple ``('filename', fileobj, 'content_type')``
        or a 4-tuple ``('filename', fileobj, 'content_type', custom_headers)``, where ``'content_type'`` is a string
        defining the content type of the given file and ``custom_headers`` a dict-like object containing additional headers
        to add for the file.
    :param auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
    :param timeout: (optional) How many seconds to wait for the server to send data
        before giving up, as a float, or a :ref:`(connect timeout, read
        timeout) <timeouts>` tuple.
    :type timeout: float or tuple
    :param allow_redirects: (optional) Boolean. Enable/disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection. Defaults to ``True``.
    :type allow_redirects: bool
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    :param verify: (optional) Either a boolean, in which case it controls whether we verify
            the server's TLS certificate, or a string, in which case it must be a path
            to a CA bundle to use. Defaults to ``True``.
    :param stream: (optional) if ``False``, the response content will be immediately downloaded.
    :param cert: (optional) if String, path to ssl client cert file (.pem). If Tuple, ('cert', 'key') pair.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    :param status:
    :return:
    """
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
                logger.warning(f"Request timeout, retry {rerequests_num} again")
                continue
            else:
                logger.error(f"{method}:{url} request timed out 3 times.")
                return None
        except Exception as e:
            raise e

        break

    # debug requests info
    logger.debug(f"{response.request.path_url} requests headers: {response.request.headers}")
    if response.request.method in ["POST", "PUT"]:
        logger.debug(f"{response.request.path_url} {response.request.method} data: {response.request.body}")

    # debug response headers
    logger.debug(f"{response.request.path_url} response headers: {response.headers}")

    if status:
        response.raise_for_status()

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


def captcha(num):
    """
    num 位数字组合
    :param num:
    :return:
    """
    code_all = []
    for code in range(1, 10 ** num):
        code_str = str(code).zfill(num)
        if code_str.startswith("00"):
            continue
        continuous = False
        for i in range(0, len(code_str) - 2):
            if abs(ord(code_str[i]) - ord(code_str[i + 1])) <= 1 and abs(
                    ord(code_str[i + 1]) - ord(code_str[i + 2])) <= 1:
                continuous = True
                break
        if continuous:
            continue

        counter = Counter(list(code_str)).values()
        if max(counter) > (num // 2) and len(counter) > (num // 2):
            continue

        code_all.append(code_str)

    random.shuffle(code_all)
    logger.info(f"Code num: {len(code_all)}")

    return code_all

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

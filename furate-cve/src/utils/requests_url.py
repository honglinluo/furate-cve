import requests
from src.utils.logger import Logger

logger = Logger(level="DEBUG")


@logger.log_duration
def requests_url(url, method='get', *args, **kwargs):
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

    if "headers" not in kwargs.keys():
        kwargs["headers"] = {"User-Agent": user_agent}
    elif "User-Agent" not in kwargs["headers"].keys():
        kwargs["headers"]["User-Agent"] = user_agent
    logger.info(f"{method}: {url}")

    response = requests.request(method=method, url=url, *args, **kwargs)

    # debug requests info
    logger.debug(f"{response.request.path_url} requests headers: {response.request.headers}")
    if response.request.method in ["post", "put"]:
        logger.debug(f"{response.request.path_url} {response.request.method} data: {response.request.body}")

    # debug response headers
    logger.debug(f"{response.request.path_url} response headers: {response.headers}")

    response.raise_for_status()

    return response


async def requests_async(url, method='get', *args, **kwargs):
    pass


if __name__ == "__main__":
    logger.info(f"run requests")
    data = {
        'page_no': 1,
        'page_size': 20,
        'rating_flag': 'true'
    }
    # response_1 = requests_url("https://ti.qianxin.com/alpha-api/v2/vuln/vuln-list", 'post', data=data)
    requests_1 = requests_url("http://www.baidu.com/", params={"wd": 1})
    # print(response.text)

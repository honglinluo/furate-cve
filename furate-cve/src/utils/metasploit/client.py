from pymetasploit3.msfrpc import MsfRpcClient
from config import *
from typing import Union
import base64
from collections import defaultdict


class MsfClient:
    def __init__(self, client=None, *args, **kwargs):
        if client:
            self.client = client
        else:
            self.cli()
        self.exploit = None

    def cli(self):
        self.client = MsfRpcClient(
            password=base64.b64decode(config["password"]).decode("utf-8"),
            username=config["username"],
            server=config["host"],
            ssl=True,
            port=config["port"],
            header=config["header"])
        if not self.client.login(
                user=config["username"],
                password=base64.b64decode(config["password"]).decode("utf-8")
        ):
            raise ConnectionError("MsfRpcClient connection failed")

    def search(self, content: str) -> dict:
        search_result = self.client.modules.search(content)
        result = defaultdict(list)
        for i in search_result:
            result[i["type"]].append(i)

        return result

    def search_all(self, modules_name: str = None) -> Union[list, dict]:
        """
        获取模块的所有数据
        :param modules_name: [auxiliary, exploit, payload]
        :return:
        """
        if modules_name:
            modules = getattr(self.client.modules, modules_name)
        else:
            modules = defaultdict(list)
            modules["auxiliary"] = self.client.modules.auxiliary
            modules["exploit"] = self.client.modules.exploits
            modules["payload"] = self.client.modules.payloads

        return modules


if __name__ == '__main__':
    msf = MsfClient()
    mod = msf.search_all()
    print(mod)

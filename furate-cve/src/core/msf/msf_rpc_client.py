import pandas as pd
from pymetasploit3.msfrpc import MsfRpcClient
from config.config_read import ConfigReader
from typing import Union, List
import base64
from collections import defaultdict


class MsfClient:
    def __init__(self, config, **kwargs):
        self.client = self.cli(config, **kwargs)
        self.exploit = None

    def cli(self, config, **kwargs):
        client = MsfRpcClient(
            password=base64.b64decode(config["PassWord"]).decode("utf-8"),
            username=config["UserName"],
            server=config["Host"],
            ssl=True,
            port=config["Port"],
            header=config["Header"],
            **kwargs
        )
        if not client.login(
                user=config["UserName"],
                password=base64.b64decode(config["PassWord"]).decode("utf-8")
        ):
            raise ConnectionError("MsfRpcClient connection failed")

        return client

    def search(self, content: str) -> dict:
        search_result = self.client.modules.search(content)
        result = defaultdict(list)
        for i in search_result:
            result[i["type"]].append(i)
        return result

    def search_all(self, modules_name: str = None) -> List[List[str]]:
        """
        获取模块的所有数据
        :param modules_name: [auxiliary, exploit, payload]
        :return:
        """
        modules = defaultdict(list)
        if modules_name:
            modules[modules_name] = getattr(self.client.modules, modules_name)
        else:
            modules["auxiliary"] = self.client.modules.auxiliary
            modules["exploit"] = self.client.modules.exploits
            modules["payload"] = self.client.modules.payloads

        model_info = []
        for model_type, names in modules.items():
            for model_name in names:
                name_split = model_name.split("/")
                model = [
                    model_name,  # 模块全名
                    model_type,  # 模块类型，'auxiliary' 'exploit' 'payload'
                    name_split[0],  # 一级模块，admin
                    name_split[1] if len(name_split) > 2 else "",  # 二级模块
                    name_split[-1],  # 模块名称
                    "" if "cve" not in name_split[-1] else name_split[-1].split("_").index("cve")
                ]

                # 增加cve编号
                if "cve" in name_split[-1]:
                    new_split = name_split[-1].split("_")
                    cve_index = new_split.index("cve")
                    model.append("_".join(new_split[cve_index: cve_index + 3]))

                else:
                    model.append("")

                model_info.append(model)

        return model_info

    def use_module(self, module_path, options=None):
        """使用指定模块并配置参数
        Args:
            module_path (str): 模块完整路径
            options (dict): 模块参数字典
        Returns:
            Module: 已配置的模块对象
        """
        module_type = module_path.split('/')[0]
        module = self.client.modules.use(module_type, module_path)
        if options:
            for k, v in options.items():
                module[k] = v
        return module


if __name__ == '__main__':
    from config.config_read import ConfigReader

    con = ConfigReader()
    msf = MsfClient(con.get("client_info"))
    mod = msf.search("CVE-2021-44228")
    print(mod)

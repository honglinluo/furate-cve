import configparser  # 读取 ini 的配置文件
import json
import os

path = "../conf/confing.ini"


class DictToObject:
    def __init__(self, dictionary):
        for k, v in dictionary.items():
            if isinstance(v, dict):
                setattr(self, k, DictToObject(v))
            else:
                setattr(self, k, v)


def config_ini(path_ini=path, section=None):
    """
    读取 ini 配置文件信息
    :param section: 需要获取的section名称
    :param path_ini: 配置文件地址
    :return: 配置文件对象
    """
    if os.path.isfile(path_ini):  # os.path.exists(path_ini) and
        con = configparser.ConfigParser()
        con.read(path_ini, encoding='utf8')
        print("配置文件读取成功")
    else:
        raise FileNotFoundError("配置文件不存在，请检查配置文件地址及文件名称")

    if section:
        return con[section]
    else:
        return con


def config_json(json_path: str, section: str = None):
    """
    读取json文件
    :param json_path:
    :param section:
    :return:
    """
    with open(json_path, 'r', encoding='utf-8') as jf:
        data = json.load(jf)
    if section:
        data = data[section]
    return DictToObject(data)


if __name__ == "__main__":
    path = r"D:\python_project\conf\confing.ini"
    data_con = config_ini(path)
    print(data_con["mysql"]["host"])

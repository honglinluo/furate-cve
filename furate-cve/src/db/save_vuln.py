from src.core.cnnvd.get_cnnvd import CNNVDXml
from src.utils import MsfClient  # MySQLConnector, TableOperator,
from config.config_read import ConfigReader

"""

"""


class Database:
    def __init__(self):
        self.conf_obj = ConfigReader()
        # self.mysql = MySQLConnector(config=conf_obg)
        self.mysql = None

    def msf(self, table_name="msf_module"):
        """
        保存msf数据
        :param table_name:
        :return:
        """
        msf = MsfClient(config=self.conf_obj.get("MSF"))
        search_result = msf.search("linux")
        print(search_result)

    def vuln(self, table_name="vulnerabilities"):
        """
        保存 漏洞 数据
        :param table_name:
        :return:
        """
        # table = TableOperator(table_name=table_name, connector=self.mysql)
        pass


if __name__ == '__main__':
    d = Database()
    d.msf()

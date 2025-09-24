from src.api.query_fofa import FOFA
import pandas as pd
import os
from src.utils import Logger

logger = Logger()
if __name__ == '__main__':
    key = '4ac7e56c095cf0b70d68eaf8ad81178a'  # 输入key
    email = '15723051314@163.com'
    domain_file = r"E:\kali_python\furate-cve\src\api\fenqile.com.csv"

    domain_list = pd.read_csv(domain_file, encoding='gbk')['域名'].to_list()
    fofa_obj = FOFA(email=email, key=key)
    r = fofa_obj.search_many(domain_list)
    r.to_csv(os.path.join(os.path.dirname(domain_file), "fofa.csv"))
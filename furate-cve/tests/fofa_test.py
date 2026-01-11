import pandas as pd
from src.utils import Logger, requests_url, build_url
from tqdm import tqdm
from src.vuln.poc import import_vuln
from config import ConfigReader

logger = Logger(level="INFO")


def fofa(vuln_poc, output_path):
    config = ConfigReader()
    fofa_data = vuln_poc.search(email=config.get('FOFA.email'), key=config.get('FOFA.key'))
    fofa_data.to_csv(output_path, index=False)
    return output_path


if __name__ == '__main__':
    module_name = "PowerPMS"
    output_path = rf"E:\kali_python\furate-cve\tests\{module_name}.csv"

    vuln_poc = import_vuln(module_name)
    # csv_file = fofa(vuln_poc, output_path)

    result = pd.read_csv(output_path)
    result["is_vuln"] = 0
    country_name_group = result.groupby('country_name')
    for country, urls in country_name_group:
        # for index in tqdm(urls.index, desc=country, total=urls.shape[0]):
        for index in urls.index:
            url_info = urls.loc[index, :]

            if "://" in url_info['host']:
                url = f"{url_info['host']}/"
            else:
                url = f"{url_info['protocol']}://{url_info['host']}"
            try:
                start = vuln_poc.start(url, timeout=3)
            except Exception:
                continue

            if start:
                result.loc[index, "is_vuln"] = 1
    result.to_csv(output_path, index=False)

import nmap
import pandas as pd
from src.utils import Logger
import socket
import ipaddress

logger = Logger()


def is_ip_address(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


@logger.log_duration
def full_port_scan(host, *args, **kwargs):
    nm = nmap.PortScanner()
    logger.info("scan host {}: {}".format(host, kwargs.get("arguments", "")))
    nm.scan(host, *args, **kwargs)
    logger.debug(nm.scaninfo())

    if nm[host].state() != "up":
        logger.error("scan state: {}".format(nm[host].state()))
        return None

    ports = []
    tcp_num = 0
    if 'tcp' in nm[host].keys():
        for proto, info in nm[host]['tcp'].items():
            ports.append([
                'tcp',
                proto,
                *info.values()
            ])
            if info.get('state') == 'open':
                tcp_num += 1

    udp_num = 0
    if 'udp' in nm[host].keys():
        for proto, info in nm[host]['udp'].items():
            ports.append([
                'udp',
                proto,
                *info.values()
            ])
            if info.get('state') == 'open':
                udp_num += 1

    ports_pd = pd.DataFrame(ports, columns=[
        'agreement',  # 协议类型
        "port",  # 端口号
        'state',  # 状态
        'reason',
        'name',  # 服务名称
        'product',  # 厂商
        'version',  # 版本号
        'extrainfo',
        'conf',
        'cpe'
    ])

    logger.info('Number of open ports: TCP {}; UDP {}'.format(tcp_num, udp_num))
    logger.info("port: {}".format(ports_pd.loc[:, "port"].values))
    return ports_pd


def resolve_dns(domain: str):
    if "://" in domain:
        domain = domain.split("://")[-1]
    if "/" in domain:
        domain = domain.split('/')[0]

    if is_ip_address(domain):
        logger.info("IP: {}".format(domain))
        return domain, {}

    logger.info("NDS parsing: {}".format(domain))
    try:
        # 获取IPv4地址（A记录）
        ipv4 = socket.gethostbyname(domain)
        # 获取所有地址记录（包含IPv6）
        addr_info = socket.getaddrinfo(domain, None)

        result = {
            'domain': domain,
            'ipv4': ipv4,
            'all_records': [x[4][0] for x in addr_info]
        }
        logger.info("NDS result: {}".format(result))
        return result['ipv4'], result
    except socket.gaierror as e:
        logger.error(f"DNS parsing Failed: {e}")


if __name__ == '__main__':
    url = 'https://www.gys7w.com'
    # url = "192.168.50.130"
    ip, nds = resolve_dns(url)
    result = full_port_scan(ip, arguments='-v')
    print(result)

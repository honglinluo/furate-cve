import importlib
import os
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec
import logging
import json

directory = Path(os.path.dirname(__file__))


class MethodDict(dict):
    """支持通过obj.key方式访问字典值的扩展字典类"""

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(f"'MethodDict' object has no attribute '{key}'")

    def __setattr__(self, key, value):
        self[key] = value


def get_vuln_info(module_name: str):
    json_file = directory.parent / "config.json"
    with open(json_file, "r") as jf:
        vuln_configs = json.load(jf)

    vuln = None
    for key, value in vuln_configs.items():
        if module_name in value.keys():
            vuln = value[module_name]

    if vuln is None:
        logging.warning("")
    else:
        logging.debug("")
    return vuln


def import_vuln(module_name: str):
    vuln = get_vuln_info(module_name)
    if vuln is None:
        raise ImportError(f"{module_name} is not found")
    module_path = os.path.join(directory, vuln['type'].lower(), vuln["file"])
    spec = spec_from_file_location(module_name, module_path)

    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return MethodDict({
        'start': module.start,
        'search': module.search
    })


__all__ = [
    "get_vuln_info",
    "import_vuln"
]

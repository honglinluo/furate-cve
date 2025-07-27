from collections import ChainMap
from .config import *

config = ChainMap({"header": header}, client_info)
__all__ = [
    "config"
]
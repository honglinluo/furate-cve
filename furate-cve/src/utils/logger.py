import logging
import os
import time
from datetime import datetime
from functools import wraps
import sys
import traceback
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler
import inspect


class Logger:
    """优化的日志处理器类，支持多日志级别和日志轮转"""

    def __init__(
            self,
            name: str = None,
            log_file: str = None,
            max_bytes: int = 10 * 1024 * 1024,  # 10MB
            backup_count: int = 5,
            level: int | str = logging.INFO,
    ):
        """
        初始化日志记录器
        参数:
            name: 日志记录器名称
            log_file: 日志文件路径
            max_bytes: 单个日志文件最大字节数
            backup_count: 保留的备份日志文件数
            log_level: 默认日志级别
        """
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.logger = logging.getLogger(name or self.__name())
        if isinstance(level, int):
            self.logger.setLevel(level)
        else:
            self.logger.setLevel(logging.getLevelName(level))

        if log_file is None:
            path_sep = os.getcwd().split(os.sep)
            index = path_sep.index('furate-cve')
            path_sep = path_sep[: index + 1]

            path_sep.extend(["logs", f"app_{current_time}.log"])
            log_file = f"{os.sep}".join(path_sep)

        self.logger.propagate = False  # 禁止传播到父logger
        # 防止重复添加handler
        if not self.logger.handlers:
            self._setup_handlers(log_file, max_bytes, backup_count)

    def __name(self):
        """
        跟去当前调用栈列表获取调用信息
        :return: 栈列表组成的字符串
        """
        project_path = os.path.dirname(sys.path[0])
        call_stack = inspect.stack()
        new_stack = [stack for stack in call_stack if project_path in stack.filename and
                     stack.filename != __file__ and '__init__.py' not in stack.filename]

        return new_stack[0][0].f_globals['__name__']

    def _setup_handlers(self, log_file: str, max_bytes: int, backup_count: int):
        """配置日志处理器"""
        # 文件处理器（带轮转）
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_formatter = logging.Formatter(
            '%(process)d > %(thread)d (%(threadName)s) | %(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)

        # 控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter(
            '%(name)s (%(lineno)s) - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def log(
            self,
            level: int,
            message: str,
            exc_info: Optional[Exception] = None,
            extra: Optional[Dict[str, Any]] = None
    ):
        """
        记录日志
        参数:
            level: 日志级别
            message: 日志消息
            exc_info: 异常信息
            extra: 额外上下文信息
        """
        self.logger.name = self.__name()
        if exc_info:
            exc_trace = traceback.format_exc()
            message = f"{message}\n{exc_trace}"

        self.logger.log(level, message, extra=extra)

    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """记录DEBUG级别日志"""
        self.log(logging.DEBUG, message, extra=extra)

    def info(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """记录INFO级别日志"""
        self.log(logging.INFO, message, extra=extra)

    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """记录WARNING级别日志"""
        self.log(logging.WARNING, message, extra=extra)

    def error(
            self,
            message: str,
            exc_info: Optional[Exception] = None,
            extra: Optional[Dict[str, Any]] = None
    ):
        """记录ERROR级别日志"""
        self.log(logging.ERROR, message, exc_info, extra)

    def critical(
            self,
            message: str,
            exc_info: Optional[Exception] = None,
            extra: Optional[Dict[str, Any]] = None
    ):
        """记录CRITICAL级别日志"""
        self.log(logging.CRITICAL, message, exc_info, extra)

    def log_duration(self, func):
        name = func.__name__

        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = func(*args, **kwargs)

                # 计算执行时间
                duration = time.time() - start_time

                # 使用Logger记录日志
                self.info(f"function {name} PASS，run time: {duration:.6f}")

                return result

            except Exception as e:
                self.error(f"function {name} FALL：{str(e)}", exc_info=None)
                raise e  # 抛出原来的异常

        return wrapper


# 创建日志实例
logger = Logger()


# 测试方法：
@logger.log_duration
def test_logging():
    logger.debug("这是一个调试信息，级别为debug.")
    logger.info("这是一条信息级别的日志。")
    try:
        a = 12
        # logger.error("发生了错误：无法打开文件 '%s'." % ('file.txt'))
        assert a == 10, '111'
    except Exception as e:
        logger.error("在处理错误时遇到问题：%s" % str(e), exc_info=True)
    aa = 1
    assert aa == 10, '111'


if __name__ == "__main__":
    test_logging()

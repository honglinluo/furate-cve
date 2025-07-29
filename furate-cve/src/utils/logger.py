import logging
import os
import time
from functools import wraps
import sys

# 配置日志的基本信息，默认输出到标准错误流
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class Logger:
    def __init__(self, name=None, level="INFO"):
        if not name:
            abs_path = sys.argv[0]
            name = os.path.relpath(abs_path, start=os.getcwd())
        self.logger = logging.getLogger(name)
        # 设定日志级别，强制转换为有效的级别
        self.logger.setLevel(logging.getLevelName(level))

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message, *args, **kwargs):
        self.logger.error(message, *args, **kwargs)

    # 可以添加更多日志级别的方法，如critical, exception等

    def with_context(self, context_manager):
        """启始上下文日志记录"""
        self.start_logging()
        context_manager.__enter__()
        yield
        context_manager.__exit__()
        self.stop_logging()

    def start_logging(self):
        logging.currentprocess().setrecursionlimit(1000000)

    def stop_logging(self):
        if hasattr(logging, 'currentprocess'):
            current_process = logging.currentprocess()
            if hasattr(current_process, 'logging_dict'):
                del current_process.logging_dict['log']
                # 可以根据需要添加或删除其他属性

    def log(self, level, message):
        try:
            method = getattr(self.logger, level.lower())
            method(message)
        except AttributeError as e:
            raise AttributeError(f"错误级别 {level} 不存在。请检查输入是否正确。")

    # 可以根据需要添加异常处理、多线程支持等功能

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
                self.info(f"function {name} PASS，run time: {duration}")

                return result

            except Exception as e:
                self.error(f"function {name} FALL：{str(e)}", exc_info=True)
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

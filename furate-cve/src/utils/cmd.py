import subprocess
from typing import Tuple
import os
from pathlib import Path
from multiprocessing import Process, active_children
import threading
from src.utils.logger import Logger
import psutil

logger = Logger()

__all__ = [
    "get_project_root",
    "get_script_dir",
    "get_week_dir",
    "process_fun",
    "kill_process",
    "get_child_processes",
    "thread_fun",
    "get_child_thread",
    "kill_thread",
    "safe_exec"
]


def get_project_root():
    """获取项目根路径（向上回溯两级）"""
    return Path(__file__).parent.parent.parent


def get_script_dir():
    """获取当前脚本所在目录"""
    return os.path.dirname(os.path.abspath(__file__))


def get_week_dir():
    return os.getcwd()


def process_fun(fun, name=None, join: int = 3, *args, **kwargs):
    """
    创建一个进程
    :param fun: 进程需要运行的方法
    :param name: 进程名称
    :param join: 进程等待时间， -1 则等待子进程运行结束
    :param args:
    :param kwargs:
    :return: 进程id
    """
    p = Process(target=fun, name=name, args=(*args,), kwargs={**kwargs})
    p.start()
    logger.info(f"Process {p.pid} was created successfully")
    if join:
        p.join(join)
        return p.pid
    else:
        p.join()
        return None


def kill_process(pid=None, name=None):
    """
    结束进程，如不填写进程id和名称时，结束所有进程
    :param pid:进程id
    :param name:进程名称
    :return:
    """
    if pid is None and name:
        pid = get_child_processes(name=name).pid

    if pid is None:
        pids = [p.pid for p in get_child_processes()]
    elif not isinstance(pid, list):
        pids = [pid]
    else:
        pids = pid

    for i in pids:
        try:
            proc = psutil.Process(i)
            proc.terminate()  # 优雅终止
            proc.wait(timeout=3)  # 等待进程结束
            logger.info(f"Process {pid} terminated successfully")
        except psutil.NoSuchProcess:
            logger.error(f"Process {pid} not found")
        except psutil.AccessDenied:
            logger.error(f"Permission denied for process {pid}")


def get_child_processes(pid=None, name=None):
    """
    获取进程信息
    :param name: 进程名称
    :param pid: 需要查询状态的pid
    :return:
    """
    if pid or name:
        for p in active_children():
            if p.pid == pid or p.name == name:
                return p
    else:
        return active_children()


def thread_fun(fun, name=None, join=3, *args, **kwargs):
    """
    在进程中创建单个线程
    :param join: 等待时间
    :param fun: 运行方法
    :param name: 线程名称
    :param args:
    :param kwargs:
    :return:
    """
    t = threading.Thread(target=fun, name=name, args=(*args,), kwargs={**kwargs})
    t.start()
    logger.info(f"Thread {t.native_id} was created successfully")
    if join:
        t.join(join)
        return t.native_id
    else:
        t.join()
        return None


def get_child_thread(tid=None, name=None):
    """
    获取线程信息，通过线程id和线程name
    :param tid: 线程id
    :param name: 线程名称
    :return:
    """
    if tid or name:
        for t in threading.enumerate():
            return t
    else:
        return threading.enumerate()


def kill_thread(tid=None, name=None):
    """
    关闭线程
    :param tid: 线程id
    :param name: 线程名称
    :return:
    """
    t = get_child_thread(tid=tid, name=name)
    t._stop()


def safe_exec(cmd: str, timeout=30, project_path=False) -> Tuple[str, str]:
    """
    执行cmd命令
    :param cmd: cmd命令
    :param timeout: 超时时间
    :param project_path: 是否拼接项目路径
    :return:
    """
    cmd_list = cmd.split()
    if project_path:
        cmd_list[1] = os.path.join(get_project_root(), cmd_list[1])

    try:
        result = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            encoding='gbk',
            shell=True
        )
        logger.debug(f"Execute the command: {cmd}")
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return "", "Command timed out"
    except Exception as e:
        return "", f"Execution failed: {str(e)}"


if __name__ == "__main__":
    print(get_week_dir())
    thread_fun(safe_exec, join=3, cmd="python src/core/sqlmap/sqlmapapi.py -s", project_path=True, process=True)
    # stdout, stderr = safe_exec("python src/core/sqlmap/sqlmapapi.py -s", project_path=True, process=True)
    # print(f"Output:\n{stdout}\nErrors:\n{stderr}")
    pid_new = get_child_processes()[0][0]
    kill_process(pid=pid_new)

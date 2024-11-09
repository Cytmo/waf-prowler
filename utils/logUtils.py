import os
import logging
import colorlog
from datetime import datetime


"""
class LoggerSingleton: 日志打印单例模式，其作用是确保在整个程序中只有一个日志实例被创建和使用。
usage:
    from util.log_utils import LoggerSingleton
    TAG="**/**.py: "
    logger = LoggerSingleton().get_logger()
"""


class LoggerSingleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LoggerSingleton, cls).__new__(cls)
            cls._instance.init_logger()
        return cls._instance

    def init_logger(self):
        self.name = 'log'
        self.level = logging.DEBUG
        time = datetime.now().strftime("%Y%m%d%H%M%S%f")
        if not os.path.exists("log"):
            os.mkdir("log")
        self.filename = 'log/' + time + '.log'
        # self.filename = 'log/' + "info_extraction" + '.log'
        logging.info("Logging to %s", self.filename)
        self.setup_logger()

    def setup_logger(self):
        # 创建一个自定义的根记录器
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.NOTSET)  # 设置根记录器的级别为最低级别

        # 移除根记录器的所有处理程序
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        # 设置logger
        # 清空logger.handlers
        logging.getLogger().handlers = []
        self.logger = logging.getLogger(name=self.name)
        self.logger.setLevel(level=self.level)

        self.logger.handlers = []
        # 初始化handler
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler(filename=self.filename)

        # 设置handler等级
        console_handler.setLevel(level=logging.INFO)
        file_handler.setLevel(level=self.level)

        # 设置日志格式
        sf_format = colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s-[line:%(lineno)d]-%(levelname)s-%(message)s",
            datefmt="%H:%M:%S",
            log_colors={
                'DEBUG': 'blue',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            })
        console_handler.setFormatter(None)

        console_handler.setFormatter(sf_format)
        
        sf_format = logging.Formatter(
            "[line:%(lineno)d]-%(levelname)s-%(message)s")
        file_handler.setFormatter(sf_format)

        # 将handler添加到logger


        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def get_logger(self):

        # 移除根记录器的所有处理程序
        for handler in logging.root.handlers[:]:
                logging.root.removeHandler(handler)

                # 创建一个新的根记录器并设置自定义配置
                root_logger = logging.getLogger()
                root_logger.setLevel(logging.NOTSET)  # 设置根记录器的级别为最低级别
        # 移除控制台输出
        return self.logger

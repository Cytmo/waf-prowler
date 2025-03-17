import json
import os
from datetime import datetime
from utils.logUtils import LoggerSingleton
import atexit

logger = LoggerSingleton().get_logger()
TAG = 'recordResUtils'

class JSONLogger:
    def __init__(self, directory='result'):
        self.directory = directory
        # 创建存放日志的文件夹（如果不存在）
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)
        # 生成文件名
        self.update_file_name()
        # 初始化缓存并从文件中加载数据
        self.cache = self.load_data()
        # 注册退出时保存数据
        atexit.register(self.save_on_exit)

    def update_file_name(self):
        # 使用当前时间戳生成新的文件名
        time = datetime.now().strftime("%Y%m%d%H%M%S")
        self.file_name = os.path.join(self.directory, f'results_{time}.json')

    def load_data(self):
        # 从文件加载数据到缓存
        if os.path.exists(self.file_name):
            with open(self.file_name, 'r') as f:
                try:
                    return json.load(f)
                except json.decoder.JSONDecodeError:
                    return []
        else:
            # 文件不存在时初始化为空列表
            return []

    def save_on_exit(self):
        # 程序退出时保存缓存中的数据到文件
        with open(self.file_name, 'w') as f:
            json.dump(self.cache, f, indent=4, ensure_ascii=False)
        logger.info(f'{TAG} Data saved to {self.file_name} on exit.')

    def log_result(self, data):
        # 将新数据追加到缓存中
        self.cache.append(data)

    def check_response_text(self, url, response_text):
        # 预处理URL
        url = url.replace('9001', '8001').replace('9002', '8002').replace('9003', '8003')

        # 检查是否有匹配条件
        if '4d2e58c872d529fba1d14ba0949b644d' in response_text:
            return True

        # 查找具有相同 URL 的条目
        logger.info(f'{TAG} check_response_text url:{url}')
        logger.info(f'{TAG} check_response_text response_text:{response_text}')
        for entry in self.cache:
            if entry['url'] == url:
                # 比较 response_text
                if '.php' in response_text and '.php' in entry['response_text']:
                    return True
                if 'root:x:0:0:root:/root:/bin/bash' in response_text and 'root:x:0:0:root:/bin/bash' in entry['response_text']:
                    return True
                if entry['response_text'] == response_text or entry['response_text'] in response_text:
                    return True

        logger.info(f'{TAG} no same url in existing_data, return False')
        # 如果没有找到相同的 URL，返回 False
        return False

import json
import os
from datetime import datetime


class JSONLogger:
    def __init__(self, directory='log'):
        # 创建存放日志的文件夹（如果不存在）
        if not os.path.exists(directory):
            os.makedirs(directory)

        # 生成唯一的文件名（使用时间戳）
        time = datetime.now().strftime("%Y%m%d%H%M%S%f")
        self.file_name = os.path.join(directory, f'results_{time}.json')

    def log_result(self, data):
        # 将数据写入新的 JSON 文件
        with open(self.file_name, 'w') as f:
            json.dump(data, f, indent=4)


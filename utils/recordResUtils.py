import json
import os
from datetime import datetime

class JSONLogger:
    def __init__(self, directory='result'):
        self.directory = directory
        # 创建存放日志的文件夹（如果不存在）
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)
        # 生成文件名并创建一个空的 JSON 文件
        self.update_file_name()
        self.create_empty_file()

    def update_file_name(self):
        # 使用当前时间戳生成新的文件名
        time = datetime.now().strftime("%Y%m%d%H%M%S")
        self.file_name = os.path.join(self.directory, f'results_{time}.json')

    def create_empty_file(self):
        # 初始化一个空的 JSON 文件
        with open(self.file_name, 'w') as f:
            json.dump([], f, indent=4, ensure_ascii=False)

    def log_result(self, data):
        # 读取现有的数据
        if not os.path.exists(self.file_name):
            self.create_empty_file()
        
        with open(self.file_name, 'r') as f:
            existing_data = json.load(f)

        # 将新数据追加到现有数据中
        existing_data.append(data)

        # 写回文件
        with open(self.file_name, 'w') as f:
            json.dump(existing_data, f, indent=4, ensure_ascii=False)


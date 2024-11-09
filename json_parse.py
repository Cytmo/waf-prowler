import json
import os
import re

# 加载 JSON 文件
# result文件夹下的最新文件
# 找到最新的文件
os.chdir("result")
files = os.listdir()
files.sort(key=lambda x: os.path.getmtime(x))
latest_file = files[-1]
# path = os.path.join('result', latest_file)
with open(latest_file, 'r') as file:
   content = file.read()
# 使用正则表达式提取所有 mutant_method 类型，支持单引号和双引号
mutant_methods = set(re.findall(r"'mutant_method'\s*:\s*'([^']+)'|\"mutant_method\"\s*:\s*\"([^\"]+)\"", content))

# 处理结果，去除 None 值
mutant_methods = {method for method_tuple in mutant_methods for method in method_tuple if method}

# 打印所有 mutant_method 类型
for method in mutant_methods:
    print(method)
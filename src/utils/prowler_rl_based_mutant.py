import copy
import json
import os
import random
import requests
import collections

from utils.prowler_mutant_methods import *
from utils.logUtils import LoggerSingleton

logger = LoggerSingleton().get_logger()
TAG = "prowler_mutant.py: "

# mutant_methods = [mutant_methods_multipart_boundary]
# mutant_methods = [mutant_methods_sql_comment_obfuscation]
# mutant_methods = [mutant_methods_add_harmless_command_for_get_request]
# mutant_methods = [mutant_methods_add_Content_Type_for_get_request]
# mutant_methods = [mutant_methods_convert_get_to_post]

# 上传载荷变异方法
mutant_methods_dedicated_to_upload = []


# 奖励函数
def reward_function(response):
    logger.info(TAG + "==>reward_function, response status code: " + str(response.status_code))
    if response.status_code == 200:
        return 1  # 成功绕过WAF
    elif response.status_code == 403:
        return -1  # 被WAF阻止
    else:
        return -0.1  # 其他错误状态


def extract_features(payload):
    # 将payload转换为字符频率统计
    char_freq = collections.Counter(payload)
    # 将字符频率统计转换为固定长度的向量
    feature_vector = [char_freq.get(c, 0) for c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789']
    return feature_vector


# 发送请求的函数
def send_request(headers, url, method, data, files):
    if method == 'GET':
        response = requests.get(url, headers=headers, params=data)
    elif method == 'POST':
        response = requests.post(url, headers=headers, data=data, files=files)
    elif method == 'PUT':
        response = requests.put(url, headers=headers, data=data, files=files)
    elif method == 'DELETE':
        response = requests.delete(url, headers=headers, data=data)
    else:
        raise ValueError("Unsupported HTTP method: " + method)
    return response


# 强化学习Agent
class RLAgent:
    def __init__(self, mutant_methods, reward_function):
        self.mutant_methods = mutant_methods
        self.reward_function = reward_function
        self.q_table = {}  # 初始化Q表

    def choose_action(self, state_vector):
        # 选择一个动作，这里可以使用ε-贪婪策略
        if random.random() < 0.1:  # 10%的概率随机选择一个动作
            action = random.choice(self.mutant_methods)
        else:
            # 选择Q值最大的动作
            q_values = [self.q_table.get((tuple(state_vector), method), 0) for method in self.mutant_methods]
            max_q_value = max(q_values)
            max_indices = [i for i, q in enumerate(q_values) if q == max_q_value]
            action = self.mutant_methods[random.choice(max_indices)]
        return action

    def learn(self, state_vector, action, reward, next_state_vector):
        # 更新Q表
        q_value = self.q_table.get((tuple(state_vector), action), 0)
        next_q_values = [self.q_table.get((tuple(next_state_vector), method), 0) for method in self.mutant_methods]
        max_next_q_value = max(next_q_values)
        self.q_table[(tuple(state_vector), action)] = q_value + 0.1 * (reward + 0.9 * max_next_q_value - q_value)


def prowler_begin_to_mutant_payloads(headers, url, method, data, files=None, deep_mutant=False):
    logger.info(TAG + "==>begin to mutant payloads")

    url_backup = copy.deepcopy(url)
    mutant_payloads = []

    if os.path.exists("config/memory.json") and not deep_mutant:
        with open("config/memory.json", "r") as f:
            try:
                memories = json.load(f)
            except json.decoder.JSONDecodeError:
                memories = []
        mem_dict = {}
        for mem in memories:
            mem_dict[mem['url']] = mem['successful_mutant_method']
        __url = url.replace('8001', '9001').replace('8002', '9002').replace('8003', '9003')
        if __url in mem_dict:
            if mem_dict[__url] in mutant_methods_config:
                mutant_method, flag = mutant_methods_config[mem_dict[__url]]

                # 调用对应的变异方法
                sub_mutant_payloads = mutant_method(headers, url, method, data, files)
                logger.info(TAG + "==>found url in memory, use method: " + mem_dict[__url])
                # keep original url for result
                mutant_payloads.extend(sub_mutant_payloads)
                for payload in mutant_payloads:
                    payload['original_url'] = url

                return mutant_payloads
    else:
        logger.info(os.getcwd())
        logger.info("memory.json not exists")

    if deep_mutant:
        logger.info(TAG + "==>deep mutant")
        headers, url, method, data, files, success = mutant_methods_change_request_method(headers, url, method, data,
                                                                                          files)
        if not success:
            return []

    # if dd_enabled:
    #     logger.info(TAG + "==>dd enabled")
    #     return dd_mutant(headers, url, method, data, files)

    # 初始化RL Agent
    agent = RLAgent(mutant_methods, reward_function)
    files = files if isinstance(files, dict) else None

    # 选择一个初始状态
    # 选择一个初始状态
    state = json.dumps({
        "headers": dict(headers),
        "url": url,
        "method": method,
        "data": data.decode('utf-8') if isinstance(data, bytes) else data,
        "files": {k: v[0] for k, v in files.items()} if files else None
    })
    state_vector = extract_features(state)

    # 选择一个动作
    action = agent.choose_action(state_vector)

    # 执行动作
    headers_copy = copy.deepcopy(headers)
    url_copy = copy.deepcopy(url)
    method_copy = copy.deepcopy(method)
    data_copy = copy.deepcopy(data)
    files_copy = copy.deepcopy(files) if files else None
    logger.info(TAG + "==>mutant method: " + str(action))
    sub_mutant_payloads = action(headers_copy, url_copy, method_copy, data_copy, files_copy)

    # 发送请求并获取响应
    response = send_request(headers_copy, url_copy, method_copy, data_copy, files_copy)

    # 计算奖励
    reward = agent.reward_function(response)

    # 更新Q表
    next_state = json.dumps({
        "headers": dict(headers),
        "url": url,
        "method": method,
        "data": data.decode('utf-8') if isinstance(data, bytes) else data,
        "files": {k: v[0] for k, v in files.items()} if files else None
    })
    next_state_vector = extract_features(next_state)
    agent.learn(state_vector, action, reward, next_state_vector)

    # 将变异后的载荷添加到结果中
    if sub_mutant_payloads:
        for sub_mutant_payload in sub_mutant_payloads:
            sub_mutant_payload['mutant_method'] = action.__name__
        mutant_payloads.extend(sub_mutant_payloads)

    if method == 'UPLOAD':
        for mutant_upload_method in mutant_methods_dedicated_to_upload:
            logger.info(TAG + "==>mutant upload method: " + str(mutant_upload_method))
            headers, url, method, data, files = mutant_upload_method(headers, url, method, data, files=data)
            mutant_payloads.append({
                'headers': headers,
                'url': url,
                'method': method,
                'data': data,
                'files': data
            })

    # 保持原始URL用于结果
    for payload in mutant_payloads:
        payload['original_url'] = url_backup

    return mutant_payloads


if __name__ == "__main__":
    headers = {
        'User-Agent': 'Prowler',
        'Content-Type': 'application/json'
    }
    url = 'http://example.com/api'
    method = 'POST'
    data = {
        'param1': 'value1',
        'param2': 'value2'
    }
    files = None

    mutant_payloads = prowler_begin_to_mutant_payloads(headers, url, method, data, files)
    for payload in mutant_payloads:
        logger.info(TAG + "==>Generated payload: " + str(payload))

import copy
import itertools
import json
import os
import random
import re
import time
import urllib.parse
import uuid
import json
import os
import requests
import http.client
import gzip
from bs4 import BeautifulSoup
import io

from stable_baselines3 import PPO
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from requests.models import Request, PreparedRequest
import requests
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from stable_baselines3 import DQN  # 使用适合离散空间的算法
from stable_baselines3.common.env_checker import check_env

from sklearn.feature_extraction.text import TfidfVectorizer
if __name__ == "__main__":
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__), '../'))
# from utils.prowler_mutant import prowler_begin_to_mutant_payloads
from utils.prowler_mutant import prowler_begin_to_mutant_payloads
from utils.prowler_rl_based_mutant import prowler_begin_to_mutant_payloads as rl_based_mutant
from utils.logUtils import LoggerSingleton
from utils.recordResUtils import JSONLogger
from utils.logUtils import LoggerSingleton
import utils.prowler_parse_raw_payload
from utils.dictUtils import content_types
from utils.prowler_mutant_methods import *

# Logger
logger = LoggerSingleton().get_logger()
# logger.setLevel("WARNING")
TAG = "prowler_rl_based_mutant.py: "

def handle_json_response(response):
    try:
        data = json.loads(response.read().decode('utf-8'))
        return data
    except json.JSONDecodeError:
        logger.warning(TAG + "==> 响应数据不是有效的 JSON 格式")
        return "解析响应失败"

def handle_html_response(response):
    try:
        # 读取响应数据
        content = response.read()

        # 检查是否需要解压缩
        if content[:2] == b'\x1f\x8b':  # Gzip 的魔术字节
            content = gzip.GzipFile(fileobj=io.BytesIO(content)).read()

        # 解码为字符串
        html_content = content.decode('utf-8')

        # 解析 HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        soup = soup.prettify()
        return soup
    except UnicodeDecodeError as e:
        logger.warning(TAG + f"==> 解析 HTML 时出错: {e}")
        return None
    except Exception as e:
        logger.warning(TAG + f"==> 处理 HTML 响应时出错: {e}")
        return None

def handle_xml_response(response):
    try:
        xml_content = response.read().decode('utf-8')
        root = ET.fromstring(xml_content)
        return root
    except ET.ParseError:
        logger.warning(TAG + "==> 响应数据不是有效的 XML 格式")
        return "解析响应失败"

def handle_gzip_response(response):
    try:
        compressed_data = response.read()
        with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz_file:
            decompressed_data = gz_file.read().decode('utf-8')
        return decompressed_data
    except Exception as e:
        logger.warning(TAG + f"==> 解压缩 Gzip 数据时出错: {e}")
        return "解析响应失败"

def handle_text_response(response):
    try:
        text_content = response.read().decode('utf-8')
        return text_content
    except UnicodeDecodeError:
        logger.warning(TAG + "==> 响应数据不是有效的文本格式")
        return "解析响应失败"



def parse_response(response):
    content_type = response.getheader('Content-Type')
    logger.debug(TAG + "==>content_type: " + str(content_type))
    if content_type is None:
        logger.warning(TAG + "==>响应头中没有 Content-Type 字段")
        return "响应头中没有 Content-Type 字段, 解析响应失败"
    if 'application/json' in content_type:
        data = handle_json_response(response)
    elif 'text/html' in content_type:
        data = handle_html_response(response)
    elif 'application/xml' in content_type or 'text/xml' in content_type:
        data = handle_xml_response(response)
    elif 'gzip' in content_type:
        data = handle_gzip_response(response)
    elif 'text/plain' in content_type:
        data = handle_text_response(response)
    else:
        logger.warning(TAG + "==>Unknown response data format, content type: " + content_type)
        data = "解析响应失败"
    logger.info(TAG + "==>parsed data: " + str(data)+ "content_type is: " + content_type)

    return data


def send_requests(prep_request):
    url = urlparse(prep_request.url)
    logger.debug(TAG + "==>url: " + str(prep_request.url))
    # print content of request
    # logger.debug(TAG + "==>prep_request: " + str(prep_request))
    conn = http.client.HTTPConnection(url.netloc)
    try:
        conn.request(prep_request.method, prep_request.url, headers=prep_request.headers, body=prep_request.body)
    except Exception as e:
        logger.error(TAG + "==>error: " + str(e))
        response = requests.Response()
        # response.text = None
        # response.status_code = None
        return response
    try:
        response = conn.getresponse()
    except Exception as e:
        logger.error(TAG + "==>error: " + str(e))
        response = requests.Response()
        # response.text = None
        # response.status_code = None
        return response
    temp_log = f"Response status: {response.status} {response.reason} {response.msg}"
    logger.info(TAG + temp_log)
    # 读取响应体内容
    
    response_body = parse_response(response)


    logger.info(TAG + str(response_body))
    response.text = response_body
    response.status_code = response.status

    # 关闭连接
    conn.close()
    return response

def process_requests(headers, url, method, data=None, files=None):
    if method == 'JSON_POST':
        method = 'POST'
        data = json.dumps(data)
    if method == 'UPLOAD':
        method = 'POST'
    raw_request = Request(method, url, headers=headers, data=data, files=files)
    prep_request = raw_request.prepare()
    # 使用http.client发送请求
    logger.debug(TAG + "==>request: " + str(prep_request))
    logger.debug(TAG + "==>request headers: " + str(prep_request.headers))
    logger.debug(TAG + "==>request body: " + str(prep_request.body))
    logger.debug(TAG + "==>request url: " + str(prep_request.url))
    logger.debug(TAG + "==>request method: " + str(prep_request.method))
    return prep_request
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, verify=False)
        elif method == 'POST':
            # logger.error(TAG + "==>jsondata: " + str(data))
            # logger.error(TAG + "==>url: " + url)
            # logger.error(TAG + "==>headers: " + str(headers))
            response = requests.post(url, headers=headers, data=data, verify=False)
        elif method == 'JSON_POST':
            response = requests.post(url, headers=headers, json=data, verify=False)
        elif method == 'UPLOAD':
            response = requests.post(url, headers=headers, files=files, verify=False)
        return response
    except AssertionError as e:
        logger.error(TAG + "==>error: " + str(e))
        return None


def run_payload(payload, host=None, port=None, waf=False):
    logger.info(TAG + "==>run payload: " + str(payload))
    url = payload['url']
    # todo: more sophiscated way to obtain waf payload
    if waf:
        url = url.replace("8001", "9001").replace("8002", "9002").replace("8003", "9003")
    # for not mutanted payload, copy url as original url
    # for mutanted payload, use 'original_url' to display result

    if 'original_url' not in payload:
        original_url = url
    else:
        original_url = payload['original_url']
        if waf:
            original_url = original_url.replace("8001", "9001").replace("8002", "9002").replace("8003", "9003")

    headers = payload['headers']
    data = payload.get('data', None)
    files = payload.get('files', None)
    verify = payload.get('verify', False)
    method = payload['method']
    processed_req = process_requests(headers, url, method, data=data, files=files)
    response = send_requests(processed_req)
    logger.info(TAG + "==>send payload to " + url)
    logger.info(TAG + "==>response: " + str(response))
    # logger.debug(TAG + "==>response: " + str(response.text))
    if response is not None:
        logger.debug(TAG + "==>response: " + str(response.text))
        result = {
            'url': url,
            'original_url': original_url,
            'payload': str(payload),
            'response_status_code': response.status_code,
            'response_text': response.text,
            'success':''
        }
    else:
        result = {
            'url': url,
            'original_url': original_url,
            'payload': str(payload),
            'response_status_code': "Error",
            'response_text': "Error",
            'success':''
        }
    return result

# 获取启用的变异方法
enabled_mutant_methods = [
    (name, func) for name, (func, enabled) in mutant_methods_config.items() if enabled
]
# 测试，仅使用 mutant_methods_modify_content_type,fake_content_type,add_harmless_command_for_get_request
# enabled_mutant_methods = [
#     ('mutant_methods_modify_content_type', mutant_methods_modify_content_type),
#     ('mutant_methods_fake_content_type', mutant_methods_fake_content_type),
#     ('mutant_methods_add_harmless_command_for_get_request', mutant_methods_add_harmless_command_for_get_request)
# ]
logger.info(TAG + "Enabled Mutant Methods: " + str(enabled_mutant_methods))
# 发送请求的函数
def send_request(url, method, headers, data, files):
    try:
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
        return response.status_code
    except requests.RequestException as e:
        logger.warning(TAG + "==> 发送请求时出错: " + str(e))
        return 0


# class WAFBypassEnv(gym.Env):
#     def __init__(self, enabled_methods, payload_for_rl):
#         super(WAFBypassEnv, self).__init__()
        
#         # 初始化初始payload
#         self.initial_payload = copy.deepcopy(payload_for_rl)
#         self.initial_payload = {
#             'headers': payload_for_rl.get('headers', None),
#             'url': payload_for_rl.get('url', None),
#             'method': payload_for_rl.get('method', None),
#             'data': payload_for_rl.get('data', None),
#             'files': payload_for_rl.get('files', None)
#         }
#         self.payload = copy.deepcopy(self.initial_payload)
        
#         # 变异方法数量
#         self.num_methods = len(enabled_methods)
        
#         # 调整后的特征维度设置
#         self.payload_dim = 100  # 增加特征维度以捕获更多信息
#         self.url_dim = 50       # 同样增加URL的特征维度
        
#         # 动作空间和状态空间
#         self.action_space = spaces.Discrete(self.num_methods)
#         self.observation_space = spaces.Box(
#             low=0, high=1,
#             shape=(self.num_methods + self.num_methods + self.payload_dim + self.url_dim,),
#             dtype=np.float32
#         )

#         # 状态初始化
#         self.state = np.zeros(self.num_methods + self.num_methods + self.payload_dim + self.url_dim, dtype=np.float32)
#         self.failed_methods = np.zeros(self.num_methods, dtype=np.float32)  # 记录失败的变异方法
#         self.action_history = np.zeros(self.num_methods, dtype=np.float32)  # 记录已经采取的动作
#         self.success = False
#         self.max_steps = 2 * self.num_methods
#         self.current_step = 0
#         self.enabled_methods = enabled_methods
        
#         # 初始化特征提取器，调整max_features参数
#         max_feature_dim = max(self.payload_dim, self.url_dim)
#         self.vectorizer = TfidfVectorizer(max_features=max_feature_dim)
#         self.fit_vectorizer()
        
#     def fit_vectorizer(self):
#         # 使用更多的文本数据来训练矢量化器，以获得更好的特征表示
#         texts = [
#             str(self.initial_payload['url']), 
#             str(self.initial_payload.get('data', '')), 
#             str(self.initial_payload.get('headers', ''))
#         ]
#         self.vectorizer.fit(texts)
        
#     def reset(self, *, seed=None, options=None):
#         self.current_step = 0
#         self.success = False
#         self.failed_methods = np.zeros(self.num_methods, dtype=np.float32)  # 重置失败记录
#         self.action_history = np.zeros(self.num_methods, dtype=np.float32)   # 重置动作历史
#         self.payload = copy.deepcopy(self.initial_payload)
#         self.state = self._get_state()
#         return self.state, {}
    
#     def extract_features(self, text, feature_dim):
#         # 从文本中提取特征，调整为新的特征维度
#         text = str(text) if not isinstance(text, str) else text
#         features = self.vectorizer.transform([text]).toarray().flatten()
#         # 填充或截断特征到指定的固定长度
#         features = features[:feature_dim]
#         return np.pad(features, (0, feature_dim - len(features)), 'constant').astype(np.float32)
    
#     def _get_state(self):
#         # 状态包含：失败方法记录 + 动作历史 + payload 特征 + url 特征
#         payload_features = self.extract_features(self.payload.get('data', ''), self.payload_dim)
#         url_features = self.extract_features(self.payload['url'], self.url_dim)
#         return np.concatenate([self.failed_methods, self.action_history, payload_features, url_features]).astype(np.float32)
    
#     def step(self, action):
#         self.current_step += 1
#         name, func = self.enabled_methods[action]
        
#         # 嵌套变异方法
#         self.action_history[action] = 1
#         payload_to_mutate = copy.deepcopy(self.payload)
#         # try:
#         self.payloads = func(
#             payload_to_mutate.get('headers', None),
#             payload_to_mutate.get('url', None),
#             payload_to_mutate.get('method', None),
#             payload_to_mutate.get('data', None),
#             payload_to_mutate.get('files', None)
#         )
#         # except Exception as e:
#         #     logger.error(f"Error applying mutation method '{name}': {e}")
#         #     self.payloads = [self.payload]
#         #     exit()
        
#         # 更新 payload 和 state
#         self.payload = self.payloads[0] if self.payloads else self.payload
#         self.state = self._get_state()
        
#         # 奖励计算和失败标记
#         try:
#             reward, self.success = self._calculate_reward()
#         except Exception as e:
#             logger.error(f"Error calculating reward: {e}")
#             reward = -50
#             self.success = False
#         if not self.success:
#             self.failed_methods[action] = 1  # 标记当前方法失败
        
#         done = self.success or self.current_step >= self.max_steps
#         truncated = False
#         info = {}
#         return self.state, reward, done, truncated, info
    
#     def _calculate_reward(self):
#         """根据 WAF 返回的状态码计算奖励"""
#         reward = -10  # 默认的负奖励
#         success = False
#         for payload in self.payloads:
#             try:
#                 # 调用 run_payload，移除不必要的 None 参数
#                 result = run_payload(payload, None,None,waf=True)
#                 status_code = result.get('response_status_code', 0)

#                 if status_code == 200:
#                     reward = 30  # 成功奖励
#                     success = True
#                     logger.warning(f"WAF Bypassed: {payload['url']}")
#                     break  # 成功绕过，退出循环
#                 # elif status_code == 400:
#                 #     reward = -10  # 请求错误，适度的负奖励
#                 elif status_code == 403:
#                     reward = -30  # 被 WAF 拦截，较大的负奖励
#                 elif 500 <= status_code < 600:
#                     reward = -20  # 服务器错误，中等负奖励
#                 else:
#                     reward = -15  # 其他状态码，适度的负奖励
#             except Exception as e:
#                 logger.error(f"Error running payload: {e}")
#                 reward = -50  # 异常情况，较大负奖励
#                 success = False
#                 break  # 发生异常，退出循环
#         return reward, success




class WAFBypassEnv(gym.Env):
    def __init__(self, enabled_methods, payload_for_rl):
        super(WAFBypassEnv, self).__init__()
        
        # 初始化初始payload
        self.initial_payload = copy.deepcopy(payload_for_rl)
        self.initial_payload = {
            'headers': payload_for_rl.get('headers', None),
            'url': payload_for_rl.get('url', None),
            'method': payload_for_rl.get('method', None),
            'data': payload_for_rl.get('data', None),
            'files': payload_for_rl.get('files', None)
        }
        self.payload = copy.deepcopy(self.initial_payload)
        
        # 变异方法数量
        self.num_methods = len(enabled_methods)
        
        # 调整后的特征维度设置
        self.payload_dim = 100  # 增加特征维度以捕获更多信息
        self.url_dim = 50       # 同样增加URL的特征维度
        
        # 动作空间和状态空间
        # 动作空间包括：
        # - 恢复原始payload的动作
        # - 跳过动作
        # - 对每个变异方法，智能体可以选择应用的次数（例如1到3次）
        # - 组合多个变异方法
        self.max_mutation_times = 3  # 允许的最大变异次数
        self.total_actions = self.num_methods * self.max_mutation_times + 2  # 加上恢复和跳过动作

        self.ACTION_RESTORE = self.total_actions - 2  # 恢复原始payload的动作索引
        self.ACTION_SKIP = self.total_actions - 1     # 跳过动作的索引

        self.action_space = spaces.MultiBinary(self.total_actions)
        self.observation_space = spaces.Box(
            low=0, high=1,
            shape=(self.total_actions + self.total_actions + self.payload_dim + self.url_dim,),
            dtype=np.float32
        )

        # 状态初始化
        self.state = np.zeros(self.total_actions + self.total_actions + self.payload_dim + self.url_dim, dtype=np.float32)
        self.failed_methods = np.zeros(self.total_actions, dtype=np.float32)  # 记录失败的变异方法
        self.action_history = np.zeros(self.total_actions, dtype=np.float32)  # 记录已经采取的动作
        self.success = False
        self.max_steps = 10  # 可以根据需要调整
        self.current_step = 0
        self.enabled_methods = enabled_methods
        
        # 初始化特征提取器，调整max_features参数
        max_feature_dim = max(self.payload_dim, self.url_dim)
        self.vectorizer = TfidfVectorizer(max_features=max_feature_dim)
        self.fit_vectorizer()
        
    def fit_vectorizer(self):
        # 使用更多的文本数据来训练矢量化器，以获得更好的特征表示
        texts = [
            str(self.initial_payload['url']), 
            str(self.initial_payload.get('data', '')), 
            str(self.initial_payload.get('headers', ''))
        ]
        self.vectorizer.fit(texts)
        
    def reset(self, *, seed=None, options=None):
        self.current_step = 0
        self.success = False
        self.failed_methods = np.zeros(self.total_actions, dtype=np.float32)  # 重置失败记录
        self.action_history = np.zeros(self.total_actions, dtype=np.float32)   # 重置动作历史
        self.payload = copy.deepcopy(self.initial_payload)
        self.state = self._get_state()
        return self.state, {}
    
    def extract_features(self, text, feature_dim):
        # 从文本中提取特征，调整为新的特征维度
        text = str(text) if not isinstance(text, str) else text
        features = self.vectorizer.transform([text]).toarray().flatten()
        # 填充或截断特征到指定的固定长度
        features = features[:feature_dim]
        return np.pad(features, (0, feature_dim - len(features)), 'constant').astype(np.float32)
    
    def _get_state(self):
        # 状态包含：失败方法记录 + 动作历史 + payload 特征 + url 特征
        payload_features = self.extract_features(self.payload.get('data', ''), self.payload_dim)
        url_features = self.extract_features(self.payload['url'], self.url_dim)
        return np.concatenate([self.failed_methods, self.action_history, payload_features, url_features]).astype(np.float32)
    
    def step(self, action):
        self.current_step += 1

        # 记录已采取的动作
        self.action_history = np.logical_or(self.action_history, action).astype(np.float32)

        if action[self.ACTION_RESTORE]:
            # 恢复原始payload
            self.payload = copy.deepcopy(self.initial_payload)
            self.payloads = [self.payload]
        elif action[self.ACTION_SKIP]:
            # 跳过，不进行任何操作
            self.payloads = [self.payload]
        else:
            # 应用选定的变异方法，考虑次数和组合
            payload_to_mutate = copy.deepcopy(self.payload)
            selected_actions = np.where(action[:self.total_actions - 2] == 1)[0]

            # 解析所选的变异方法和次数
            for act in selected_actions:
                method_index = act // self.max_mutation_times
                times = (act % self.max_mutation_times) + 1  # 次数从1开始

                name, func = self.enabled_methods[method_index]
                for _ in range(times):
                    try:
                        payloads = func(
                            payload_to_mutate.get('headers', None),
                            payload_to_mutate.get('url', None),
                            payload_to_mutate.get('method', None),
                            payload_to_mutate.get('data', None),
                            payload_to_mutate.get('files', None)
                        )
                        # 假设每个变异方法返回一个列表，这里取第一个结果
                        payload_to_mutate = payloads[0] if payloads else payload_to_mutate
                    except Exception as e:
                        logger.error(f"Error applying mutation method '{name}': {e}")
                        self.failed_methods[act] = 1  # 标记当前方法失败
                        break  # 跳出当前循环，尝试下一个方法

            self.payloads = [payload_to_mutate]
            self.payload = payload_to_mutate

        # 更新状态
        self.state = self._get_state()

        # 奖励计算和失败标记
        try:
            reward, self.success = self._calculate_reward()
        except Exception as e:
            logger.error(f"Error calculating reward: {e}")
            reward = -50
            self.success = False

        done = self.success or self.current_step >= self.max_steps
        truncated = False
        info = {}
        return self.state, reward, done, truncated, info
    
    def _calculate_reward(self):
        """根据 WAF 返回的状态码计算奖励"""
        reward = -10  # 默认的负奖励
        success = False
        # 若生成的payload过长，直接返回负奖励
        if len(self.payload['url']) > 2000:
            return -50, False
        for payload in self.payloads:
            try:
                # 调用 run_payload，移除不必要的 None 参数
                result = run_payload(payload, waf=True)
                status_code = result.get('response_status_code', 0)

                if status_code == 200:
                    reward = 50  # 成功奖励
                    success = True
                    logger.warning(f"WAF Bypassed: {payload['url']}")
                    break  # 成功绕过，退出循环
                elif status_code == 403:
                    reward = -30  # 被 WAF 拦截，较大的负奖励
                elif 500 <= status_code < 600:
                    reward = -20  # 服务器错误，中等负奖励
                else:
                    reward = -15  # 其他状态码，适度的负奖励
            except Exception as e:
                logger.error(f"Error running payload: {e}")
                reward = -50  # 异常情况，较大负奖励
                success = False
                break  # 发生异常，退出循环
        return reward, success

def initialize_model(payload, enabled_mutant_methods, model_path="ppo_waf_bypass"):
    """初始化模型，如果已存在则加载模型，否则创建新模型"""
    try:
        model = PPO.load(model_path, device="cuda")
        # 检查模型的环境状态空间是否与当前环境匹配
        env = WAFBypassEnv(enabled_mutant_methods, payload)
        if model.observation_space.shape != env.observation_space.shape:
            logger.warning("Observation space mismatch, reinitializing model.")
            model = create_new_model(env)
        else:
            model.set_env(env)
    except FileNotFoundError:
        logger.warning("Model not found, creating a new model.")
        env = WAFBypassEnv(enabled_mutant_methods, payload)
        model = create_new_model(env)
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        env = WAFBypassEnv(enabled_mutant_methods, payload)
        model = create_new_model(env)
    return model

def create_new_model(env):
    """创建新的 PPO 模型"""
    return PPO("MlpPolicy", env, verbose=1, device="cuda")
def train_model(model, payloads, enabled_mutant_methods, total_timesteps=5000):
    """遍历 payloads 并逐个训练模型"""
    for i, payload_for_rl in enumerate(payloads):
        env = WAFBypassEnv(enabled_mutant_methods, payload_for_rl)
        
        # 更新模型的环境
        model.set_env(env)
        logger.warning(f"Training on payload {i + 1}/{len(payloads)}")
        
        # 可选的休眠观察
        time.sleep(5)
        model.learn(total_timesteps=total_timesteps)
        
        # 保存中间状态（可选）
        model.save(f"ppo_waf_bypass_payload_{i + 1}")

    # 最终保存模型
    model.save("ppo_waf_bypass")
def test_model(model, env):
    """测试模型在特定环境中的性能"""
    obs, _ = env.reset()
    done = False
    total_reward = 0

    while not done:
        action, _ = model.predict(obs, deterministic=True)
        obs, reward, done, truncated, info = env.step(action)
        total_reward += reward
        print(f"Action: {action}, Reward: {reward}")

    print(f"Total Reward: {total_reward}")


def prowler_begin_to_mutant_payload_with_rl(headers, url, method, data, files=None):
    logger.warning(TAG + "==> Begin mutating payloads with RL")
    mutant_payloads = []

    # 创建环境，使用初始的请求数据
    env = WAFBypassEnv(enabled_mutant_methods, {
        'headers': headers,
        'url': url,
        'method': method,
        'data': data,
        'files': files
    })

    # 加载预训练的模型
    model = PPO.load("ppo_waf_bypass", device="cuda")

    # 重置环境，获取初始观察
    obs, _ = env.reset()
    done = False
    total_reward = 0

    # 使用模型进行推理，直到成功绕过 WAF 或达到最大步骤数
    while not done:
        # 使用模型预测下一个动作
        action, _states = model.predict(obs, deterministic=True)

        # 执行动作，获取新的状态和奖励
        obs, reward, done, truncated, info = env.step(action)
        total_reward += reward

        logger.debug(f"Action: {action}, Reward: {reward}")

    logger.info(f"Total Reward: {total_reward}")

    logger.info(TAG + "==> RL suggested mutant methods: " + str(env.action_history))
    logger.info(TAG + "==> RL suggested payload: " + str(env.payload))
    logger.info(TAG + "==> RL suggested state: " + str(env.state))
    logger.info(TAG + "==> RL failed methods: " + str(env.failed_methods))
    # 获取最终的变异后的 payload
    mutant_payload = env.payload

    # 将变异后的 payload 添加到列表中
    mutant_payloads.append(mutant_payload)

    return mutant_payloads
if __name__ == "__main__":
    # 添加参数清空模型，重新训练
    if "--reset" in sys.argv:
        if os.path.exists("ppo_waf_bypass.zip"):
            os.remove("ppo_waf_bypass.zip")
    # 加载并解析 payloads
    payloads = utils.prowler_parse_raw_payload.prowler_begin_to_sniff_payload("config/payload/json")

    # 初始化模型
    model = initialize_model(payloads[0], enabled_mutant_methods)
    
    # 训练模型
    train_model(model, payloads, enabled_mutant_methods, total_timesteps=5000)

    # 测试模型
    test_env = WAFBypassEnv(enabled_mutant_methods, payloads[0])
    model = PPO.load("ppo_waf_bypass", device="cuda")
    test_model(model, test_env)

import copy
import itertools
import json
import os
import random
import re
import urllib.parse
import uuid
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
from utils.logUtils import LoggerSingleton
import utils.prowler_parse_raw_payload
from utils.dictUtils import content_types
from utils.prowler_mutant_methods import *

# Logger
logger = LoggerSingleton().get_logger()
TAG = "rl.py: "


# 获取启用的变异方法
enabled_mutant_methods = [
    (name, func) for name, (func, enabled) in mutant_methods_config.items() if enabled
]
print("Enabled Mutant Methods:", enabled_mutant_methods)

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
        print(f"Request failed: {e}")
        return 0

# 自定义环境类
class WAFBypassEnv(gym.Env):
    def __init__(self, enabled_methods, payload_for_rl):
        super(WAFBypassEnv, self).__init__()
        self.initial_payload = payload_for_rl
        self.payload = copy.deepcopy(self.initial_payload)
        self.url = str(self.initial_payload['url'])
        self.num_methods = len(enabled_methods)
        self.payload_dim = 10
        self.url_dim = 10
        # 离散的动作空间
        self.action_space = spaces.Discrete(self.num_methods)
        self.observation_space = spaces.Box(low=0, high=1, shape=(self.num_methods + self.payload_dim + self.url_dim,), dtype=np.float32)

        self.state = np.zeros(self.num_methods + self.payload_dim + self.url_dim, dtype=np.float32)
        self.success = False
        self.max_steps = 10
        self.current_step = 0
        self.enabled_methods = enabled_methods
        self.vectorizer = TfidfVectorizer(max_features=10)
        self.fit_vectorizer()
        
    def fit_vectorizer(self):
        texts = [str(self.initial_payload), self.url]
        self.vectorizer.fit(texts)
        
    def reset(self, *, seed=None, options=None):
        self.current_step = 0
        self.success = False
        self.payload = copy.deepcopy(self.initial_payload)
        payload_features = self.extract_features(self.payload)
        url_features = self.extract_features(self.url)
        self.state = np.concatenate([np.zeros(self.num_methods), payload_features, url_features]).astype(np.float32)
        return self.state, {}
    
    def extract_features(self, text):
        text = str(text) if not isinstance(text, str) else text
        features = self.vectorizer.transform([text]).toarray().flatten()
        return np.pad(features, (0, 10 - len(features)), 'constant').astype(np.float32)
    
    def step(self, action):
        self.current_step += 1
        
        # 应用变异方法并更新状态
        name, func = self.enabled_methods[action]
        # check if files is in payload
        if not self.payload['files']:
            self.payload['files'] = None
        self.payloads = func(self.payload['headers'], self.payload['url'], self.payload['method'], self.payload['data'], self.payload['files'])
        
        # 更新 payload 并提取新特征
        self.payload = self.payloads[0] if self.payloads else self.payload
        payload_features = self.extract_features(self.payload)
        url_features = self.extract_features(self.payload['url'])
        self.state[self.num_methods:self.num_methods + self.payload_dim] = payload_features
        self.state[self.num_methods + self.payload_dim:] = url_features
        
        # 计算奖励并判断是否成功
        reward = -10  # 默认奖励
        self.success = False
        for payload in self.payloads:
            self.success, reward = self.interact_with_environment(payload)
            if self.success:
                break

        done = self.success or self.current_step >= self.max_steps
        truncated = False
        info = {}
        return self.state, reward, done, truncated, info
    
    def interact_with_environment(self, payload):
        # if payload['data']:
        #     if not isinstance(payload['data'], bytes):
        # add files key to payload
        payload['files'] = None
        if payload['files']:
            status_code = send_request(payload['url'], payload['method'], payload['headers'], payload['data'], payload['files'])
        else:
            status_code = send_request(payload['url'], payload['method'], payload['headers'], payload['data'], None)
        success = (status_code == 200)
        reward = 50 if success else -10
        if success:
            logger.info(TAG + "WAF Bypassed: " + payload['url'])
        return success, reward

payloads = utils.prowler_parse_raw_payload.prowler_begin_to_sniff_payload("test/test_payloads")
payload_for_rl = payloads[0]
# change method to post
payload_for_rl['method'] = 'POST'
# 初始化环境并检查
env = WAFBypassEnv(enabled_mutant_methods, payload_for_rl)
check_env(env)

# 创建并训练 DQN 模型（适合离散空间的算法）
model = DQN("MlpPolicy", env, gamma=0.99, learning_rate=3e-2, verbose=1, device="cuda")
model.learn(total_timesteps=5000)
model.save("dqn_waf_bypass")

# 测试模型
model = DQN.load("dqn_waf_bypass", device="cuda")
obs, _ = env.reset()
done = False
total_reward = 0

while not done:
    action, _states = model.predict(obs, deterministic=True)
    obs, reward, done, truncated, info = env.step(action)
    total_reward += reward
    print(f"Action: {action}, Reward: {reward}")

print(f"Total Reward: {total_reward}")

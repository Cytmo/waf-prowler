import copy
import itertools
import json
import os
import random
import re
import urllib.parse
import uuid

import requests
if __name__ == "__main__":
    import sys
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from utils.logUtils import LoggerSingleton
from utils.dictUtils import content_types
from utils.prowler_mutant_methods import *
logger = LoggerSingleton().get_logger()
TAG = "rl.py: "
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from stable_baselines3 import SAC
from stable_baselines3.common.env_checker import check_env

# 获取启用的方法
enabled_mutant_methods = [
    method for method, (func, enabled) in mutant_methods_config.items() if enabled
]
print("Enabled Mutant Methods:", enabled_mutant_methods)

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

# 自定义环境定义
class WAFBypassEnv(gym.Env):
    def __init__(self, enabled_methods):
        super(WAFBypassEnv, self).__init__()
        
        # 动作空间和状态空间的维度为启用方法的数量
        self.num_methods = len(enabled_methods)
        self.action_space = spaces.Box(low=-1, high=1, shape=(self.num_methods,), dtype=np.float32)
        self.observation_space = spaces.Box(low=0, high=1, shape=(self.num_methods,), dtype=np.float32)
        
        # 初始化状态
        self.state = np.zeros(self.num_methods, dtype=np.float32)
        self.success = False
        self.max_steps = 10
        self.current_step = 0

    def reset(self, *, seed=None, options=None):
        self.state = np.zeros(self.num_methods, dtype=np.float32)
        self.current_step = 0
        self.success = False
        return self.state, {}

    def step(self, action):
        self.current_step += 1
        scaled_action = (action + 1) / 2
        self.state = np.clip(self.state + scaled_action, 0, 1)
        
        self.success, reward = self.interact_with_environment(self.state)
        done = self.success or self.current_step >= self.max_steps
        truncated = False
        return self.state, reward, done, truncated, {}

    def interact_with_environment(self, state):
        success = send_payload_with_mutations(state)
        reward = 10 if success else -10
        return success, reward

def send_payload_with_mutations(state):
    return np.random.rand() > 0.5

# 初始化环境，传入启用的方法
env = WAFBypassEnv(enabled_mutant_methods)
check_env(env)

# 创建并训练SAC模型
model = SAC("MlpPolicy", env, gamma=0.99, learning_rate=3e-4, verbose=1, device="cuda")
model.learn(total_timesteps=50000)

# 保存模型
model.save("sac_waf_bypass")

# 测试模型
model = SAC.load("sac_waf_bypass", device="cuda")
obs, _ = env.reset()
done = False
total_reward = 0

while not done:
    action, _states = model.predict(obs, deterministic=True)
    obs, reward, done, truncated, info = env.step(action)
    total_reward += reward
    print(f"Action: {action}, Reward: {reward}")

print(f"Total Reward: {total_reward}")
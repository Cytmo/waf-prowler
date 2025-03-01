<div align="center">
  <img src="./images/logo.png" alt="WAF Prowler Logo" width="800"/>
  <h1 align="center">WAF Prowler</h1>
  <h3 align="center">基于协议层的WAF脆弱性检测</h3>
</div>

<!-- PROJECT SHIELDS -->

<p align="center">
  <a href="https://github.com/Cytmo/waf-prowler/graphs/contributors">
    <img alt="GitHub License" src="https://img.shields.io/github/contributors/Cytmo/waf-prowler.svg?style=">
  </a>
  <a href="https://github.com/Cytmo/waf-prowler/network/members">
    <img alt="GitHub release" src="https://img.shields.io/github/forks/Cytmo/waf-prowler.svg?style=">
  </a>
  <a href="https://github.com/Cytmo/waf-prowler/stargazers">
    <img alt="Tech Report" src="https://img.shields.io/github/stars/Cytmo/waf-prowler.svg?style">
  </a>
  <a href="https://img.shields.io/github/issues/Cytmo/waf-prowler.svg">
    <img alt="Demo" src="https://img.shields.io/github/issues/Cytmo/waf-prowler.svg?style">
  </a>
</p>

<p align="center">
  <br />
  <a href="https://github.com/Cytmo/waf-prowler"><strong>探索本项目的文档 »</strong></a>
  <br />
  <br />
  <a href="https://github.com/Cytmo/waf-prowler/issues">报告Bug</a>
  ·
  <a href="https://github.com/Cytmo/waf-prowler/issues">提出新特性</a>
</p>


WAF-Prowler是作为一个开箱即用的 Web 恶意载荷变异工具，可用于评测网络防火墙抵御未知攻击的能力，本项目的功能特性为：
1. 针对传统绕过技术因高度特定化而导致的通用性不足问题，本项目采用了基于协议层的 WAF 绕过机制。这种机制的核心是在不改动攻击载荷关键数据的前提下，通过修改协议层的内容来实现绕过 WAF 的目的，从而大大增强了方法的通用性；
2. 鉴于传统 WAF 绕过工具多依赖于穷举测试，导致效率低下，本项目引入了强化学习技术。该技术将载荷的变异方法视为动作空间的一部分，并将从 WAF 接收到的 HTTP 响应作为反馈信号，以此来指导更高效、更精准的载荷变异过程，从而实现 WAF 的有效绕过；
3. 为了解决如何高效选取和组合变异策略的问题，我们开发了一种基于权重的 Delta-Debugging 算法，能够较为准确地给出最有可能成功绕过 WAF 的变异策略及其组合。此外，针对实践中可能出现的相似载荷重复变异问题，本项目还引入了基于记忆的策略权重调整机制，利用先前运行结果来动态调整不同变异策略的权重，进而提高后续变异策略选择的精确度。


## 目录

- [上手指南](#上手指南)
  - [环境准备](#环境准备)
  - [运行参数](#运行参数)
  - [启动测试环境](#启动测试环境)
  - [运行测试程序](#运行测试程序)
  - [目录结构](目录结构)

## 上手指南
### 下载项目
```bash
git clone https://github.com/Cytmo/waf-prowler.git
```
### 环境准备
```bash
pip install -r requirements.txt
```
### 运行参数
`-m` enable mutants
### 启动测试环境
Use `set_test_env.sh` to set up the test environments
### 运行测试程序
Use `run.sh` to run the tests or run the following command:
`python3 main.py -m` to run the tests with mutants and memory
`python3 main.py -m --disable-memory` to run the tests with mutants and without memory
`python3 main.py --disable-memory -ds` to run the tests without memory and shortcut disabled

## 目录结构
```
.
├── Mutation-Methods.md
├── README.md
├── bash.sh
├── clean.sh
├── config
│   ├── log_config.ini
│   ├── memory.json
│   ├── payload
│   └── payload1
├── json_parse.py
├── main.py
├── profile.stats
├── requirements.txt
├── result
├── run.sh                        # 运行脚本
├── set_test_env.sh
├── test
│   ├── PHP5
│   ├── gowaf_modified
│   ├── gowaf_modified.go
│   ├── log
│   ├── run_modified_waf.sh
│   ├── test.go1
│   ├── test.py
│   └── test_payloads
├── test-envs
│   └── a-simple-waf
├── test.py
└── utils
    ├── dictUtils.py
    ├── log
    ├── logUtils.py
    ├── prowler_feature_extract.py
    ├── prowler_mutant.py
    ├── prowler_mutant_methods.py       # 变异方法具体实现
    ├── prowler_parse_raw_payload.py
    ├── prowler_process_requests.py
    ├── prowler_rl copy.py
    ├── prowler_rl.py
    ├── prowler_rl_based_mutant.py
    ├── prowler_send_request.py
    └── recordResUtils.py
```

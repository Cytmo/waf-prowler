import hashlib
import json
import os
import re
from utils.logUtils import LoggerSingleton
import utils.prowler_parse_raw_payload
import utils.prowler_process_requests
import argparse
import time
import requests

logger = LoggerSingleton().get_logger()
TAG = "main.py: "

argparse = argparse.ArgumentParser()
# argparse.add_argument("-f", "--folder", default="../data",
#                       help="The folder to be scanned")
# false 默认单进程 true 多进程
argparse.add_argument("-mp", "--multiprocess", default="false",
                      help="if use multiprocess")
argparse.add_argument("--test", help="if use test payload",action="store_true")
argparse.add_argument("-r", "--raw", default="config/payload/json",
                      help="Path to raw payload files")
argparse.add_argument("--disable-memory", help="if disable memory",action="store_true")
argparse.add_argument("-w","--wsl",default="true",help="if use wsl",action="store_true")
argparse.add_argument("-m","--mutant",help="if use mutant",action="store_true")
argparse.add_argument("--host", help="host ip",default="localhost")
argparse.add_argument("-ds", "--disable-shortcut", help="disable shortcut, which will end exec when has any successful payload",action="store_true")
argparse.add_argument("-p", "--plain", help="use text format payload",action="store_true")
argparse.add_argument("--port", help="port",default="8001")
# 是否启用强化学习
argparse.add_argument("--rl", help="if use reinforcement learning",action="store_true")

# 输入扫描的路径
args = argparse.parse_args()

# if using wsl
if args.wsl == True:
    logger.info(TAG+"==>Using wsl")
    # get windows host ip by running cat /etc/resolv.conf | grep nameserver
    # windows_host_ip = os.popen("cat /etc/resolv.conf | grep nameserver").read().split()[1]
    # args.host = windows_host_ip.strip()
    logger.info(TAG+"==>windows host ip: "+args.host)
if args.disable_memory == True:
    logger.info(TAG+"==>Disable memory")
    if os.path.exists("config/memory.json"):
        os.remove("config/memory.json")
    else:
        logger.info(TAG+"==>Memory file does not exist")
# if test
if args.test == True:
    args.raw = "test/test_payloads"
    logger.info(TAG+"==>Using test payload")
if args.plain == True:
    logger.info(TAG+"==>Using plain payload")
    args.raw = "config/payload/plain"
if args.disable_shortcut == True:
    enable_shortcut = False 
else:
    enable_shortcut = True
# if use reinforcement learning
if args.rl == True:
    logger.info(TAG+"==>Using reinforcement learning")
def generate_unique_id(entry):
    # 生成唯一标识符，基于url、method、data和payload
    unique_str = f"{entry['url']}{entry['payload']}{entry['original_url']}"
    return hashlib.md5(unique_str.encode()).hexdigest()

def deduplicate_results(input_file, output_file):
    with open(input_file, 'r') as f:
        results = json.load(f)

    seen_ids = set()
    deduplicated_results = []

    for entry in results:
        unique_id = generate_unique_id(entry)
        if unique_id not in seen_ids:
            seen_ids.add(unique_id)
            deduplicated_results.append(entry)

    with open(output_file, 'w') as f:
        json.dump(deduplicated_results, f, indent=4)
def main():
    # read raw payload folder
    logger.info(TAG + "==>raw payload folder: " + args.raw)
    if args.plain:
        payloads = utils.prowler_parse_raw_payload.prowler_begin_to_sniff_payload(args.raw,plain=True)
    payloads = utils.prowler_parse_raw_payload.prowler_begin_to_sniff_payload(args.raw)
    # send payloads to address without waf
    results = utils.prowler_process_requests.prowler_begin_to_send_payloads(args.host,args.port,payloads)
    formatted_results = json.dumps(results, indent=4,ensure_ascii=False)
    logger.debug(TAG + "==>results: " + formatted_results)
    for result in results:
        if result['response_status_code'] == 200:
            logger.info(TAG + "==>url: " + result['url'] + " success")
        else:
            if result['response_text'] is not None:
                logger.warning(TAG + "==>url: " + result['url'] + " failed" + " response: " + result['response_text'])
            else:
                logger.warning(TAG + "==>url: " + result['url'] + " failed")
    # send payloads to address with waf
    if args.mutant:
        results = utils.prowler_process_requests.prowler_begin_to_send_payloads(args.host,args.port,payloads,waf=True,PAYLOAD_MUTANT_ENABLED=True,enable_shortcut=enable_shortcut,rl=args.rl)
    else:
        results = utils.prowler_process_requests.prowler_begin_to_send_payloads(args.host,args.port,payloads,waf=True,PAYLOAD_MUTANT_ENABLED=False,enable_shortcut=enable_shortcut)
    # result 去重
    # 使用集合去重
    seen = set()
    unique_results = []

    for result in results:
        # 定义一个元组作为去重的依据
        identifier = (result['url'], result['response_status_code'], json.dumps(result['response_text']),json.dumps(result['payload']),result['original_url']) 
        if identifier not in seen:
            seen.add(identifier)
            unique_results.append(result)
    results = unique_results
    formatted_results = json.dumps(results, indent=6,ensure_ascii=False)
    logger.debug(TAG + "==>results: " + formatted_results)
    for result in results:
        if result['response_status_code'] == 200:
            logger.info(TAG + "==>url: " + result['url'] + " success")
        else:
            logger.info(TAG + "==>url: " + result['url'] + " failed" + " response: " + str(result['response_text']))
    # 统计每个url的尝试次数和是否绕过
    url_attempts = {}
    for result in results:
        url = result['original_url']
        if url not in url_attempts:
            url_attempts[url] = {'attempts': 0, 'success': 0}
        url_attempts[url]['attempts'] += 1
        if result['success'] == True:
            url_attempts[url]['success'] += 1

    for url, attempts in url_attempts.items():
        logger.warning(TAG + "==>url: " + url + " attempts: " + str(attempts['attempts']) + " success: " + str(attempts['success']))
    # 输出总的尝试次数和成功次数及成功率
    total_attempts = sum(attempts['attempts'] for attempts in url_attempts.values()) - len(url_attempts)
    total_success = sum(attempts['success'] for attempts in url_attempts.values())
    success_rate = total_success / total_attempts if total_attempts > 0 else 0
    logger.info(TAG + "==>Total attempts(initial attempt not included): " + str(total_attempts) + " Total success: " + str(total_success) + " Success rate: " + str(success_rate))
    memories = []
    for result in results:
        if result['success'] ==True:
            # 使用正则表达式提取mutant_method的值
            pattern = r"'mutant_method':\s*'([^']+)'"
            match = re.search(pattern, result['payload'])

            if match:
                mutant_method = match.group(1)
                memory = {
                    'url': result['original_url'],
                    'successful_mutant_method': mutant_method,
                }
                memories.append(memory)
    # 读取或初始化内存文件
    memory_file_path = "config/memory.json"
    try:
        if not os.path.exists(memory_file_path):
            os.makedirs(os.path.dirname(memory_file_path), exist_ok=True)
            old_memory = []
            with open(memory_file_path, "w") as f:
                json.dump(old_memory, f, indent=4)
        else:
            with open(memory_file_path, "r") as f:
                old_memory = json.load(f)
    except json.decoder.JSONDecodeError:
        logger.error(f"{TAG} ==> 'memory.json' is empty or corrupted")
        old_memory = []

    # 去重处理
    # 使用集合来避免重复的条目
    unique_memories = {json.dumps(mem, sort_keys=True) for mem in memories}
    memories = [json.loads(mem) for mem in unique_memories]

    # 将旧的内存条目映射到一个以 URL 和 successful_mutant_method 为键的字典中
    old_memory_dict = {(mem['url'], mem['successful_mutant_method']): mem for mem in old_memory}

    # 比较并更新内存条目
    new_memory = []
    for memory in memories:
        key = (memory['url'], memory['successful_mutant_method'])
        if key not in old_memory_dict:
            new_memory.append(memory)
        else:
            # 如果有相同的URL和successful_mutant_method，比较其他属性是否需要更新
            old_mem = old_memory_dict[key]
            if any(memory[k] != old_mem[k] for k in memory if k not in ['url', 'successful_mutant_method']):
                old_memory.remove(old_mem)
                new_memory.append(memory)

    # 更新memory.json中的内容
    if new_memory:
        updated_memory = old_memory + new_memory
        with open(memory_file_path, "w") as f:
            json.dump(updated_memory, f, indent=4)
        logger.info(f"{TAG} ==> Updated 'memory.json' with new entries.")

logger.info(TAG + "************************ start *****************************")
T1 = time.perf_counter()  # 计时

main()

T2 = time.perf_counter()  # 计时结束
logger.info(TAG + "************************* end ******************************")


# 打印程序配置
logger.info(TAG+'程序配置: %s' % args)
# 打印程序耗时
logger.info(TAG+'程序运行时间:%s毫秒' % ((T2 - T1)*1000))
# 打印日志文件路径，获取log文件夹下最新的日志文件
newest_log_file = sorted([os.path.join("log", f) for f in os.listdir("log")], key=os.path.getctime)[-1]
logger.info(TAG + "日志文件路径: %s" % newest_log_file)
newest_result_file = sorted([os.path.join("result", f) for f in os.listdir("result")], key=os.path.getctime)[-1]
deduplicate_results(newest_result_file, newest_result_file)
logger.info(TAG + "结果文件路径: %s" % newest_result_file)

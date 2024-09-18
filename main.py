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
argparse.add_argument("-p", "--plain", help="use text format payload",action="store_true")
argparse.add_argument("--port", help="port",default="8001")

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
        logger.info(TAG+"==>The file does not exist")
# if test
if args.test == True:
    args.raw = "test/test_payloads"
    logger.info(TAG+"==>Using test payload")
if args.plain == True:
    logger.info(TAG+"==>Using plain payload")
    args.raw = "config/payload/plain"
def main():

    # read raw payload folder
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
        results = utils.prowler_process_requests.prowler_begin_to_send_payloads(args.host,args.port,payloads,waf=True,PAYLOAD_MUTANT_ENABLED=True)
    else:
        results = utils.prowler_process_requests.prowler_begin_to_send_payloads(args.host,args.port,payloads,waf=True,PAYLOAD_MUTANT_ENABLED=False)
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
    # 读取之前的memory，如果没有则创建一个新的
    if not os.path.exists("config/memory.json"):
        with open("config/memory.json", "w") as f:
            json.dump([], f)
    with open("config/memory.json", "r") as f:
        try:
            old_memory = json.load(f)
        except json.decoder.JSONDecodeError:
            logger.error(TAG + "==>memory.json is empty")
            old_memory = []
    # 比较是否有新的memory
    new_memory = []
    for memory in memories:
        if memory not in old_memory:
            new_memory.append(memory)
    # 更新memory.json中的内容
    if new_memory:
        # 将旧的和新的内存条目合并
        updated_memory = old_memory + new_memory
        
        with open("config/memory.json", "w") as f:
            # 格式化输出
            json.dump(updated_memory, f, indent=4)
logger.info(TAG + "************************ start *****************************")
T1 = time.perf_counter()  # 计时

main()

T2 = time.perf_counter()  # 计时结束
logger.info(TAG + "************************* end ******************************")


# 打印程序配置
logger.info(TAG+'程序配置: %s' % args)
# 打印程序耗时
logger.info(TAG+'程序运行时间:%s毫秒' % ((T2 - T1)*1000))

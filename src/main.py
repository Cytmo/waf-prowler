import argparse
import hashlib
import json
import os
import re
import socket
import time

from utils.logUtils import LoggerSingleton
from utils.prowler_parse_raw_payload import prowler_begin_to_sniff_payload
from utils.prowler_process_requests import prowler_begin_to_send_payloads


logger = LoggerSingleton().get_logger()
TAG = "main.py: "
enable_shortcut = True


def parse_arguments():
    """配置命令行参数"""
    parser = argparse.ArgumentParser(
        description="WAF Bypass Testing Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("-mp", "--multiprocess", default="false",
                          choices=["true", "false"], help="Enable multiprocess")
    parser.add_argument("-r", "--raw", default="config/payload/json", help="Path to raw payload files")
    parser.add_argument("--host",  default="localhost", help="Target host ip")
    parser.add_argument("--port", default=8001, type=int, help="Target port")

    parser.add_argument("--test-payloads", help="Use test-payloads payload", action="store_true")
    parser.add_argument("--disable-memory", help="Disable memory", action="store_true")
    parser.add_argument("-w", "--wsl", default="true", action="store_true", help="Use wsl")
    parser.add_argument("-m", "--mutant", help="Use mutant", action="store_true")
    parser.add_argument("-ds", "--disable-shortcut",
                          help="Disable shortcut, which will end exec when has any successful payload",
                          action="store_true")
    parser.add_argument("-p", "--plain", help="Use text format payload", action="store_true")
    # 是否启用强化学习
    parser.add_argument("--rl", help="Use reinforcement learning mode", action="store_true")

    return parser.parse_args()


def configure_settings(args):
    # if using wsl
    if args.wsl:
        logger.info(TAG+"==>Using wsl")
        # get windows host ip by running cat /etc/resolv.conf | grep nameserver
        # windows_host_ip = os.popen("cat /etc/resolv.conf | grep nameserver").read().split()[1]
        # args.host = windows_host_ip.strip()
        logger.info(TAG+"==>windows host ip: "+args.host)
    if args.disable_memory:
        logger.info(TAG+"==>Disable memory")
        if os.path.exists("config/memory.json"):
            os.remove("config/memory.json")
        else:
            logger.info(TAG+"==>Memory file does not exist")
    if args.test_payloads:
        logger.info(TAG+"==>Using test-payloads payload")
        args.raw = "test-payloads/test_payloads"
    if args.plain:
        logger.info(TAG+"==>Using plain payload")
        args.raw = "config/payload/plain"
    if args.disable_shortcut:
        enable_shortcut = False
    # Use reinforcement learning
    if args.rl:
        logger.info(TAG+"==>Using reinforcement learning")


def generate_unique_id(entry):
    # 生成唯一标识符，基于url、method、data和payload
    unique_str = f"{entry['url']}{entry['payload']}{entry['original_url']}"
    return hashlib.md5(unique_str.encode()).hexdigest()


def deduplicate_results(results):
    # result 去重, 使用集合去重
    seen = set()
    unique_results = []

    for result in results:
        # 定义一个元组作为去重的依据
        identifier = (result['url'], result['response_status_code'], json.dumps(result['response_text']),
                      json.dumps(result['payload']), result['original_url'])
        if identifier not in seen:
            seen.add(identifier)
            unique_results.append(result)
    results = unique_results
    formatted_results = json.dumps(results, indent=6, ensure_ascii=False)
    logger.debug(TAG + "==>results: " + formatted_results)
    for result in results:
        if result['response_status_code'] == 200:
            logger.info(TAG + "==>url: " + result['url'] + " success")
        else:
            logger.info(TAG + "==>url: " + result['url'] + " failed" + " response: " + str(result['response_text']))


def generate_statistic(results):
    # 统计每个url的尝试次数和是否绕过
    url_attempts = {}
    for result in results:
        url = result['original_url']
        if url not in url_attempts:
            url_attempts[url] = {'attempts': 0, 'success': 0}
        url_attempts[url]['attempts'] += 1
        if result['success']:
            url_attempts[url]['success'] += 1

    for url, attempts in url_attempts.items():
        logger.warning(TAG + "==>url: " + url + " attempts: " + str(attempts['attempts']) + " success: " + str(attempts['success']))
    # 输出总的尝试次数和成功次数及成功率
    total_attempts = sum(attempts['attempts'] for attempts in url_attempts.values()) - len(url_attempts)
    total_success = sum(attempts['success'] for attempts in url_attempts.values())
    success_rate = total_success / total_attempts if total_attempts > 0 else 0
    logger.info(TAG + "==>Total attempts(initial attempt not included): " + str(total_attempts) + " Total success: " + str(total_success) + " Success rate: " + str(success_rate))


def update_memory(results):
    """更新内存文件"""
    memories = {}
    for result in results:
        if result['success'] == True:
            # 使用正则表达式提取mutant_method的值
            pattern = r"'mutant_method':\s*'([^']+)'"
            match = re.search(pattern, result['payload'])

            if match:
                mutant_method = match.group(1)
                url = result['original_url']

                # 如果该url不存在，创建一个新的列表
                if url not in memories:
                    memories[url] = []

                # 添加mutant_method到对应url的列表中，确保不重复
                if mutant_method not in memories[url]:
                    memories[url].append(mutant_method)

    # 读取或初始化内存文件
    memory_file_path = "config/memory.json"
    try:
        if not os.path.exists(memory_file_path):
            os.makedirs(os.path.dirname(memory_file_path), exist_ok=True)
            old_memory = {}
            with open(memory_file_path, "w") as f:
                json.dump(old_memory, f, indent=4)
        else:
            with open(memory_file_path, "r") as f:
                old_memory = json.load(f)
    except json.decoder.JSONDecodeError:
        logger.error(f"{TAG} ==> 'memory.json' is empty or corrupted")
        old_memory = {}

    # 更新 old_memory 中的内容
    for url, mutant_methods in memories.items():
        if url not in old_memory:
            old_memory[url] = mutant_methods
        else:
            # 将新方法添加到旧方法列表中，并去重
            old_memory[url].extend(mutant_methods)
            old_memory[url] = list(set(old_memory[url]))

    # 将更新后的内容写回 memory.json
    with open(memory_file_path, "w") as f:
        json.dump(old_memory, f, indent=4)
    logger.info(f"{TAG} ==> Updated 'memory.json' with new entries.")


def check_url_reachable(host, port):
    """
    检查目标网址是否可达
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # 设置超时时间为5秒
        sock.connect((host, port))
        sock.close()
        return True
    except socket.error:
        return False


def main(args):
    configure_settings(args)
    # 判断目标网址是否可达，不可达则不测试
    if not check_url_reachable(args.host, args.port):
        logger.error(TAG + "==>Target website is unreachable, please use --host and --port to "
                           "specify the target address.")
        return
    logger.info(TAG + "==>Target website: " + args.host + ":" + str(args.port))

    # read raw payload folder
    logger.info(TAG + "==>raw payload folder: " + args.raw)
    if args.plain:
        payloads = prowler_begin_to_sniff_payload(args.raw, plain=True)
    else:
        payloads = prowler_begin_to_sniff_payload(args.raw)
    # send payloads to address without waf

    results = prowler_begin_to_send_payloads(args.host, args.port, payloads)
    formatted_results = json.dumps(results, indent=4, ensure_ascii=False)
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
        results = prowler_begin_to_send_payloads(args.host, args.port, payloads, waf=True, PAYLOAD_MUTANT_ENABLED=True,
                                                 enable_shortcut=enable_shortcut, rl=args.rl)
    else:
        results = prowler_begin_to_send_payloads(args.host, args.port, payloads, waf=True, PAYLOAD_MUTANT_ENABLED=False,
                                                 enable_shortcut=enable_shortcut)

    deduplicate_results(results)
    generate_statistic(results)
    update_memory(results)


if __name__ == "__main__":
    logger.info(TAG + "************************ start *****************************")
    T1 = time.perf_counter()  # 计时

    args = parse_arguments()
    main(args)

    T2 = time.perf_counter()  # 计时结束
    logger.info(TAG + "************************* end ******************************")

    # 打印程序配置
    logger.info(TAG + '程序配置: %s' % args)
    # 打印程序耗时
    logger.info(TAG+'程序运行时间:%s毫秒' % ((T2 - T1)*1000))
    # 打印日志文件路径，获取log文件夹下最新的日志文件
    newest_log_file = sorted([os.path.join("./log", f) for f in os.listdir("./log")], key=os.path.getctime)[-1]
    logger.info(TAG + "日志文件路径: %s" % newest_log_file)
    try:
        # 打印结果文件路径，获取result文件夹下最新的结果文件
        newest_result_file = sorted([os.path.join("../result", f) for f in os.listdir("../result")], key=os.path.getctime)[-1]
        logger.info(TAG + "结果文件路径: %s" % newest_result_file)
    except:
        pass
    # logger.info(TAG + "结果文件路径: %s" % newest_result_file)

import json
import os
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

argparse.add_argument("-w","--wsl",default="true",help="if use wsl",action="store_true")

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
            logger.warning(TAG + "==>url: " + result['url'] + " success")
        else:
            logger.warning(TAG + "==>url: " + result['url'] + " failed" + " response: " + result['response_text'])
    # send payloads to address with waf
    results = utils.prowler_process_requests.prowler_begin_to_send_payloads(args.host,args.port,payloads,waf=True)
    formatted_results = json.dumps(results, indent=4,ensure_ascii=False)
    logger.debug(TAG + "==>results: " + formatted_results)
    for result in results:
        if result['response_status_code'] == 200:
            logger.warning(TAG + "==>url: " + result['url'] + " success")
        else:
            logger.warning(TAG + "==>url: " + result['url'] + " failed" + " response: " + result['response_text'])
    pass





logger.info(TAG + "************************ start *****************************")
T1 = time.perf_counter()  # 计时

main()

T2 = time.perf_counter()  # 计时结束
logger.info(TAG + "************************* end ******************************")

# 打印程序耗时
logger.info(TAG+'程序运行时间:%s毫秒' % ((T2 - T1)*1000))

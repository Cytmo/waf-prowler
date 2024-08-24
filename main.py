from utils.logUtils import LoggerSingleton
import argparse
import time
logger = LoggerSingleton().get_logger()
TAG = "main.py: "

# 添加命令行参数, 默认扫描"../data"文件夹
argparse = argparse.ArgumentParser()
# argparse.add_argument("-f", "--folder", default="../data",
#                       help="The folder to be scanned")
# false 默认单进程 true 多进程
argparse.add_argument("-mp", "--multiprocess", default="false",
                      help="if use multiprocess")

# 输入扫描的路径
args = argparse.parse_args()



def main():
    pass





logger.info(TAG + "************************ start *****************************")
T1 = time.perf_counter()  # 计时

main()

T2 = time.perf_counter()  # 计时结束
logger.info(TAG + "************************* end ******************************")

# 打印程序耗时
logger.info(TAG+'程序运行时间:%s毫秒' % ((T2 - T1)*1000))

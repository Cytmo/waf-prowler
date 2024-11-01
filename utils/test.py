import http.client
from urllib.parse import urlparse
import logging

# 假设 `send_requests` 函数已经定义，包含超时和错误处理
def send_requests(prep_request, timeout=1):
    url = urlparse(prep_request.get('url'))
    logger.debug("==>url: " + str(prep_request.get('url')))
    
    conn = http.client.HTTPConnection(url.netloc, timeout=timeout)
    
    try:
        conn.request(
            method=prep_request.get('method'),
            url=url.path,  # 注意仅传递路径部分
            body=prep_request.get('body'),
            headers=prep_request.get('headers')
        )
    except Exception as e:
        logger.error("==>error in sending request: " + str(e))
        return None

    try:
        response = conn.getresponse()
        response_body = response.read().decode('utf-8')  # 读取并解码响应体
    except Exception as e:
        logger.error("==>error in receiving response: " + str(e))
        return None
    finally:
        conn.close()
    
    return {"status": response.status, "body": response_body}

# 日志记录
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)



def test_send_requests():
    # 定义测试 payload
    payload = {
        'url': 'http://localhost:9001/upload',  # 测试服务器的 URL
        'method': 'POST',
        'headers': {
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7',
            'Connection': 'close',
            'Content-Length': '183',
            'Content-Type': 'multipart/form-data; boundary=2bcb6fa9edc628db004536f88eb6c869'
        },
        'data': b'--2bcb6fa9edc628db004536f88eb6c869\r\nContent-Disposition: form-data; name="file"; filename="1.php"\r\nContent-Type: application/x-httpd-php\r\n\r\n123\r\n--2bcb6fa9edc628db004536f88eb6c869--\r\n'
    }

    # 调用 `send_requests` 函数
    response = send_requests(payload)

    # 输出结果
    if response:
        print("Status Code:", response["status"])
        print("Response Body:", response["body"])
    else:
        print("Request failed or timed out")

# 执行测试
test_send_requests()

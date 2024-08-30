import json
import requests
from utils.prowler_mutant import prowler_begin_to_mutant_payloads
from utils.logUtils import LoggerSingleton
from utils.recordResUtils import JSONLogger
import http.client
from urllib.parse import urlparse
from requests.models import Request, PreparedRequest
logger = LoggerSingleton().get_logger()
resLogger = JSONLogger()
TAG = "prowler_process_requests.py: "

def send_requests(prep_request):
    url = urlparse(prep_request.url)
    logger.debug(TAG + "==>url: " + str(url))
    conn = http.client.HTTPConnection(url.netloc)
    conn.request(prep_request.method, prep_request.url, headers=prep_request.headers, body=prep_request.body)
    response = conn.getresponse()
    print(f"Response status: {response.status} {response.reason}")
    response.text = response.reason
    response.status_code = response.status
    # 关闭连接
    conn.close()
    return response
def process_requests(headers, url, method, data=None, files=None):
    if method == 'JSON_POST':
        method = 'POST'
        data = json.dumps(data)
    if method == 'UPLOAD':
        method = 'POST'
    raw_request = Request(method, url, headers=headers, data=data, files=files)
    prep_request = raw_request.prepare()
    # 使用http.client发送请求
    logger.debug(TAG + "==>request: " + str(prep_request))
    logger.debug(TAG + "==>request headers: " + str(prep_request.headers))
    logger.debug(TAG + "==>request body: " + str(prep_request.body))
    logger.debug(TAG + "==>request url: " + str(prep_request.url))
    logger.debug(TAG + "==>request method: " + str(prep_request.method))
    return prep_request
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, verify=False)
        elif method == 'POST':
            # logger.error(TAG + "==>jsondata: " + str(data))
            # logger.error(TAG + "==>url: " + url)
            # logger.error(TAG + "==>headers: " + str(headers))
            response = requests.post(url, headers=headers, data=data, verify=False)
        elif method == 'JSON_POST':
            response = requests.post(url, headers=headers, json=data, verify=False)
        elif method == 'UPLOAD':
            response = requests.post(url, headers=headers, files=files, verify=False)
        return response
    except AssertionError as e:
        logger.error(TAG + "==>error: " + str(e))
        return None


def run_payload(payload, host, port, waf=False):
    url = payload['url']
    # for not mutanted payload, copy url as original url
    # for mutanted payload, use 'original_url' to display result
    if 'original_url' not in payload:
        original_url = url
    else:
        original_url = payload['original_url']
    # todo: more sophiscated way to obtain waf payload
    if waf:
        url = url.replace("8001", "9001")
    headers = payload['headers']
    data = payload.get('data', None)
    files = payload.get('files', None)
    verify = payload.get('verify', False)
    method = payload['method']
    processed_req = process_requests(headers, url, method, data=data, files=files)
    response = send_requests(processed_req)
    logger.info(TAG + "==>send payload to " + url)
    logger.info(TAG + "==>response: " + str(response))
    # logger.debug(TAG + "==>response: " + str(response.text))
    if response is not None:
        logger.debug(TAG + "==>response: " + str(response.text))
        result = {
            'url': url,
            'original_url': original_url,
            'payload': str(payload),
            'response_status_code': response.status_code,
            'response_text': response.text
        }
    else:
        result = {
            'url': url,
            'original_url': original_url,
            'payload': str(payload),
            'response_status_code': "Error",
            'response_text': "Error"
        }
    return result



def prowler_begin_to_send_payloads(host,port,payloads,waf=False):
    results = []
    
    for payload in payloads:
        # get the payload data
        result = run_payload(payload, host, port, waf)
        results.append(result)
        if result.get('response_status_code') == 200:
            logger.warning(TAG + "==>url: " + result['url'] + " success")
        else:
            logger.warning(TAG + "==>url: " + result['url'] + " failed" + " response: " + result['response_text'])
            url = payload['url']
            headers = payload['headers']
            data = payload.get('data', None)
            files = payload.get('files', None)
            verify = payload.get('verify', False)
            method = payload['method']
            processed_req = process_requests(headers, url, method, data=data, files=files)
            mutant_payloads = prowler_begin_to_mutant_payloads(processed_req.headers, processed_req.url, processed_req.method, data=processed_req.body)
            for mutant_payload in mutant_payloads:
                result = run_payload(mutant_payload, host, port, waf)
                formatted_results = json.dumps(result, indent=4,ensure_ascii=False)
                print(formatted_results)
                results.append(result)
                if result.get('response_status_code') == 200:
                    logger.warning(TAG + "==>url: " + result['url'] + " success after mutant")
                    # 把success的payload记录到结果文件
                    # resLogger.log_result(mutant_payload)
                    break
                else:
                    logger.warning(TAG + "==>url: " + result['url'] + " failed after mutant " + " response: " + result['response_text'])
    return results
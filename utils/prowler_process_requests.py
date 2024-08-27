import requests
from utils.prowler_mutant import prowler_begin_to_mutant_payloads
from utils.logUtils import LoggerSingleton
from utils.recordResUtils import JSONLogger
logger = LoggerSingleton().get_logger()
resLogger = JSONLogger()
TAG = "prowler_parse_raw_payload.py: "
def process_requests(headers, url, method, data=None, files=None):

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
    if waf:
        url = url.replace("8001", "9001")
    headers = payload['headers']
    data = payload.get('data', None)
    files = payload.get('files', None)
    verify = payload.get('verify', False)
    method = payload['method']
    if method == 'GET':
        response = process_requests(headers, url, method, data=data)
    elif method == 'POST':
        response = process_requests(headers, url, method, data=data)
    elif method == 'JSON_POST':
        response = process_requests(headers, url, method, data=data)
    elif method == 'UPLOAD':
        response = process_requests(headers, url, method, files=files)
    logger.info(TAG + "==>send payload to " + url)
    logger.info(TAG + "==>response: " + str(response))
    logger.debug(TAG + "==>response: " + str(response.text))
    if response is not None:
        result = {
            'url': url,
            'payload': payload,
            'response_status_code': response.status_code,
            'response_text': response.text
        }
    else:
        result = {
            'url': url,
            'payload': payload,
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
            mutant_payloads = prowler_begin_to_mutant_payloads(headers, url, method, data, files)
            for mutant_payload in mutant_payloads:
                result = run_payload(mutant_payload, host, port, waf)
                results.append(result)
                if result.get('response_status_code') == 200:
                    logger.warning(TAG + "==>url: " + result['url'] + " success after mutant")
                    # 把success的payload记录到结果文件
                    resLogger.log_result(mutant_payload)
                    break
                else:
                    logger.warning(TAG + "==>url: " + result['url'] + " failed after mutant " + " response: " + result['response_text'])
    return results
import requests
from utils.logUtils import LoggerSingleton
logger = LoggerSingleton().get_logger()
TAG = "prowler_parse_raw_payload.py: "
def process_requests(headers, url, method, data=None, json_data=None, files=None):
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, verify=False)
        elif method == 'POST':
            response = requests.post(url, headers=headers, data=data, verify=False)
        elif method == 'JSON_POST':
            response = requests.post(url, headers=headers, json=json_data, verify=False)
        elif method == 'UPLOAD':
            response = requests.post(url, headers=headers, files=files, verify=False)
        return response
    except Exception as e:
        logger.error(TAG + "==>error: " + str(e))
        return None

def prowler_begin_to_send_payloads(host,port,payloads,waf=False):
    results = []
    if not waf:
        for payload in payloads:
            # get the payload data
            url = payload['url']
            headers = payload['headers']
            data = payload.get('data', None)
            verify = payload.get('verify', False)
            method = payload['method']
            response = process_requests(headers, url, method, data=data)
            logger.info(TAG + "==>send payload to " + url)
            logger.info(TAG + "==>response: " + str(response))
            result = {
                'url': url,
                'payload': payload,
                'response_status_code': response.status_code,
                'response_text': response.text
            }
            results.append(result)
    else:
        for payload in payloads:
            # get the payload data
            url = payload['url']
            headers = payload['headers'] 
            data = payload.get('data', None)
            verify = payload.get('verify', False)
            method = payload['method']
            url = url.replace("8001","9001")
            response = process_requests(headers, url, method, data=data)
            logger.info(TAG + "==>send payload to " + url)
            logger.info(TAG + "==>response: " + str(response))
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
            results.append(result)
    return results
import copy
import json
import os
import time
import requests
# from utils.prowler_mutant import prowler_begin_to_mutant_payloads
from utils.prowler_mutant_methods import mutant_methods_map
from utils.prowler_mutant import prowler_begin_to_mutant_payloads

from utils.prowler_rl import prowler_begin_to_mutant_payload_with_rl
from utils.prowler_rl import send_requests as send_requests_for_rl
from utils.logUtils import LoggerSingleton
from utils.recordResUtils import JSONLogger
import http.client
import gzip
from bs4 import BeautifulSoup
import io
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from requests.models import Request, PreparedRequest
logger = LoggerSingleton().get_logger()
resLogger = JSONLogger()
TAG = "prowler_process_requests.py: "
HTTP_CONNECTION_TIMEOUT = 0.2

def handle_json_response(response):
    try:
        data = json.loads(response.read().decode('utf-8'))
        return data
    except json.JSONDecodeError:
        logger.warning(TAG + "==> 响应数据不是有效的 JSON 格式")
        return "解析响应失败"

def handle_html_response(response):
    try:
        # 读取响应数据
        content = response.read()

        # 检查是否需要解压缩
        if content[:2] == b'\x1f\x8b':  # Gzip 的魔术字节
            content = gzip.GzipFile(fileobj=io.BytesIO(content)).read()

        # 解码为字符串
        html_content = content.decode('utf-8')

        # 解析 HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        soup = soup.prettify()
        return soup
    except UnicodeDecodeError as e:
        logger.warning(TAG + f"==> 解析 HTML 时出错: {e}")
        return None
    except Exception as e:
        logger.warning(TAG + f"==> 处理 HTML 响应时出错: {e}")
        return None

def handle_xml_response(response):
    try:
        xml_content = response.read().decode('utf-8')
        root = ET.fromstring(xml_content)
        return root
    except ET.ParseError:
        logger.warning(TAG + "==> 响应数据不是有效的 XML 格式")
        return "解析响应失败"

def handle_gzip_response(response):
    try:
        compressed_data = response.read()
        with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz_file:
            decompressed_data = gz_file.read().decode('utf-8')
        return decompressed_data
    except Exception as e:
        logger.warning(TAG + f"==> 解压缩 Gzip 数据时出错: {e}")
        return "解析响应失败"

def handle_text_response(response):
    try:
        text_content = response.read().decode('utf-8')
        return text_content
    except UnicodeDecodeError:
        logger.warning(TAG + "==> 响应数据不是有效的文本格式")
        return "解析响应失败"



def parse_response(response):
    content_type = response.getheader('Content-Type')
    logger.debug(TAG + "==>content_type: " + str(content_type))
    if content_type is None:
        logger.warning(TAG + "==>响应头中没有 Content-Type 字段")
        return "响应头中没有 Content-Type 字段, 解析响应失败"
    if 'application/json' in content_type:
        data = handle_json_response(response)
    elif 'text/html' in content_type:
        data = handle_html_response(response)
    elif 'application/xml' in content_type or 'text/xml' in content_type:
        data = handle_xml_response(response)
    elif 'gzip' in content_type:
        data = handle_gzip_response(response)
    elif 'text/plain' in content_type:
        data = handle_text_response(response)
    else:
        logger.warning(TAG + "==>Unknown response data format, content type: " + content_type)
        data = "解析响应失败"
    logger.info(TAG + "==>parsed data: " + str(data)+ "content_type is: " + content_type)

    return data

def send_requests(prep_request, timeout=HTTP_CONNECTION_TIMEOUT):
    url = urlparse(prep_request.url)
    logger.debug(TAG + "==>url: " + str(prep_request.url))
    # print content of request
    # logger.debug(TAG + "==>prep_request: " + str(prep_request))
    conn = http.client.HTTPConnection(url.netloc, timeout=timeout)
    try:
        conn.request(prep_request.method, prep_request.url, headers=prep_request.headers, body=prep_request.body)
    except Exception as e:
        logger.error(TAG + "==>error: " + str(e))
        response = requests.Response()
        # response.text = None
        # response.status_code = None
        return response
    try:
        response = conn.getresponse()
    except Exception as e:
        logger.error(TAG + "==>error: " + str(e))
        response = requests.Response()
        # response.text = None
        # response.status_code = None
        return response
    temp_log = f"Response status: {response.status} {response.reason} {response.msg}"
    logger.info(TAG + temp_log)
    # 读取响应体内容
    
    response_body = parse_response(response)


    logger.info(TAG + str(response_body))
    response.text = response_body
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


def run_payload_for_rl(payload, host=None, port=None, waf=True):
    logger.info(TAG + "==>run payload: " + str(payload))
    url = payload['url']
    # todo: more sophiscated way to obtain waf payload
    if waf:
        url = url.replace("8001", "9001").replace("8002", "9002").replace("8003", "9003")
    # for not mutanted payload, copy url as original url
    # for mutanted payload, use 'original_url' to display result

    if 'original_url' not in payload:
        original_url = url
    else:
        original_url = payload['original_url']
        if waf:
            original_url = original_url.replace("8001", "9001").replace("8002", "9002").replace("8003", "9003")
    # processed_req = process_requests(headers, url, method, data=data, files=files)
    processed_req = {
        "url": url,
        "headers": payload.get('headers', None),
        "method": payload.get('method', None),
        "body": payload.get('body', None),
    }
    # print(payload)
    # print(processed_req)
    # exit()
    response = send_requests_for_rl(processed_req)
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
            'response_text': response.text,
            'success':''
        }
    else:
        result = {
            'url': url,
            'original_url': original_url,
            'payload': str(payload),
            'response_status_code': "Error",
            'response_text': "Error",
            'success':''
        }
    return result
def run_payload(payload, host, port, waf=False):
    logger.info(TAG + "==>run payload: " + str(payload))
    url = payload['url']
    # todo: more sophiscated way to obtain waf payload
    if waf:
        url = url.replace("8001", "9001").replace("8002", "9002").replace("8003", "9003")
    # for not mutanted payload, copy url as original url
    # for mutanted payload, use 'original_url' to display result

    if 'original_url' not in payload:
        original_url = url
    else:
        original_url = payload['original_url']
        if waf:
            original_url = original_url.replace("8001", "9001").replace("8002", "9002").replace("8003", "9003")

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
            'response_text': response.text,
            'success':''
        }
    else:
        result = {
            'url': url,
            'original_url': original_url,
            'payload': str(payload),
            'response_status_code': "Error",
            'response_text': "Error",
            'success':''
        }
    return result



def prowler_begin_to_send_payloads(host,port,payloads,waf=False,PAYLOAD_MUTANT_ENABLED=False,enable_shortcut=True,enable_dd=False,rl=False):
    results = []
    rl_backup = rl
    # 字典：记录成功的mutant_method
    success_method = []
    for payload in payloads:
        # get the payload data
        result = run_payload(payload, host, port, waf)
        rl = rl_backup
        if result.get('response_status_code') == 200:
            logger.warning(TAG + "==>url: " + result['url'] + " success")
            result['success'] = True
            results.append(result)
            resLogger.log_result( result)
        else:
            result['success'] = False
            results.append(result)
            if result['response_text'] is not None:
                logger.warning(TAG + "==>url: " + result['url'] + " failed" + " response: " + result['response_text'])
            else:
                logger.warning(TAG + "==>url: " + result['url'] + " failed")
            url = payload['url']
            headers = payload['headers']
            data = payload.get('data', None)
            files = payload.get('files', None)
            verify = payload.get('verify', False)
            method = payload['method']
            processed_req = process_requests(headers, url, method, data=data, files=files)
            logger.info(TAG + "==>PAYLOAD_MUTANT_ENABLED: " + str(PAYLOAD_MUTANT_ENABLED))
            if PAYLOAD_MUTANT_ENABLED:
                i = 0
                
                success_after_mutant = False 
                if method == 'GET':
                    deep_mutant = True
                else:
                    deep_mutant = False
                end_mutant = False
                # if method == 'GET':
                #     deep_mutant = True
                # 修改终止条件为 end_mutant == False
                while not end_mutant:
                    mutant_payloads = []
                    
                    # for success_method_item in success_method:
                    #     headers_copy = copy.deepcopy(processed_req.headers)
                    #     url_copy = copy.deepcopy(processed_req.url)
                    #     method_copy = copy.deepcopy(processed_req.method)
                    #     data_copy = copy.deepcopy(processed_req.body)
                    #     files_copy = None
                    #     # 从mutant_methods列表中取出对应的方法
                    #     success_method_item = mutant_methods_map[success_method_item]
                    #     sub_mutant_payloads = success_method_item(headers_copy, url_copy, method_copy, data_copy, files_copy)
                    #     if not sub_mutant_payloads:
                    #         logger.warning(TAG + "==>no sub mutant payloads for method: " + str(success_method_item.__name__))
                    #     for sub_mutant_payload in sub_mutant_payloads:
                    #         sub_mutant_payload['mutant_method'] = success_method_item.__name__
                    #     mutant_payloads.extend(sub_mutant_payloads)
                    # 获取变异后的 payloads
                    enable_shortcut_for_mutant = enable_shortcut
                    if len(mutant_payloads) == 0:
                        if rl:
                        # mutant_payloads = prowler_begin_to_mutant_payloads(processed_req.headers, processed_req.url, processed_req.method, data=processed_req.body, deep_mutant=deep_mutant)
                            mutant_payloads = prowler_begin_to_mutant_payload_with_rl(processed_req.headers, processed_req.url, processed_req.method, data=processed_req.body)
                        else:
                            mutant_payloads = prowler_begin_to_mutant_payloads(processed_req.headers, processed_req.url, processed_req.method, data=processed_req.body, deep_mutant=deep_mutant,enable_shortcut=enable_shortcut_for_mutant)
                    if len(mutant_payloads) == 0:
                        # use normal mutant
                        rl = False  
                        mutant_payloads = prowler_begin_to_mutant_payloads(processed_req.headers, processed_req.url, processed_req.method, data=processed_req.body, deep_mutant=deep_mutant,enable_shortcut=enable_shortcut_for_mutant)
                    # 遍历 mutant_payloads 执行 payload
                    for mutant_payload in mutant_payloads:
                        if rl:
                            result = run_payload_for_rl(mutant_payload, host, port, waf)
                        else:
                            result = run_payload(mutant_payload, host, port, waf)
                        formatted_results = json.dumps(result, indent=4, ensure_ascii=False)
                        logger.debug(TAG + "==>results: " + formatted_results)
                        # 检查返回状态码以及结果
                        if result.get('response_status_code') == 200 and resLogger.check_response_text(result['original_url'], result['response_text']):
                            logger.warning(TAG + "==>url: " + result['url'] + " success after mutant")
                            result['success'] = True
                            results.append(result)
                            # 记录成功的 payload
                            resLogger.log_result(result)
                            success_after_mutant = True
                            print(mutant_payload)
                            success_method.append(mutant_payload['mutant_method'])
                            if enable_shortcut:
                                break
                        else:
                            result['success'] = False
                            results.append(result)
                            logger.warning(TAG + "==>url: " + result['url'] + " failed after mutant " + " response: " + str(result['response_text']))
                    if not success_after_mutant:
                                                # 若强化学习失败，使用普通变异
                        if rl:
                            rl = False
                            logger.warning(TAG + "==>url: " + result['url'] + " rl failed, use normal mutant")
                    if not success_after_mutant and deep_mutant:
                        logger.warning(TAG + "==>url: " + result['url'] + " deep mutant failed")
                        end_mutant = True
                    # 如果还未成功并且 deep_mutant 为 False，进行深度变异
                    if not success_after_mutant and not deep_mutant:
                        #     time.sleep(10)
                        if method != 'GET':
                            end_mutant = True
                        else:
                            deep_mutant = True
                        logger.warning(TAG + "==>url: " + result['url'] + " begin deep mutant")
                        
                    # 如果深度变异也失败，终止变异过程
                    # elif not success_after_mutant and deep_mutant:
                    #     logger.warning(TAG + "==>url: " + result['url'] + " deep mutant failed")
                    #     end_mutant = True
                    if success_after_mutant and enable_shortcut:
                        end_mutant = True
                    if not enable_shortcut:
                        i += 1
                        if i ==2:
                            end_mutant = True
    return results
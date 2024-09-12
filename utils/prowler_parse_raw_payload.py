#!/usr/bin/env python3

import json
from utils.logUtils import LoggerSingleton
import os
logger = LoggerSingleton().get_logger()
TAG = "prowler_parse_raw_payload.py: "


def get_unformatted_payload(json_path):

    # init
    ret = {}

    # processing JSON file
    with open(json_path) as f:
        try:
            jdata = json.load(f)
        except Exception as e:
            print(
                'An error occurred while loading file {}: file not in JSON format ({})'
                .format(json_path, e)
            )
            logger.warning(
                'An error occurred while loading file {}: file not in JSON format ({})'
                .format(json_path, e)
            )
            return {}

    # url
    url = jdata.get('url', None)
    ret['url'] = None if not url else url
    # if url is localhost, change it to 127.0.0.1
    # if ret['url']:
    #     if 'localhost' in ret['url']:
    #         ret['url'] = ret['url'].replace('localhost', '127.0.0.1')
    # headers
    headers = jdata.get('headers', None)
    ret['headers'] = None if not headers else headers
    
    # remove host , origin , referer, content-length from headers
    if ret['headers']:
        if 'Host' in ret['headers']:
            del ret['headers']['Host']
        if 'Origin' in ret['headers']:
            del ret['headers']['Origin']
        if 'Referer' in ret['headers']:
            del ret['headers']['Referer']
        if 'Content-Length' in ret['headers']:
            del ret['headers']['Content-Length']
    # data
    data = jdata.get('data', None)

    # verify
    verify = jdata.get('verify', None)
    ret['verify'] = verify if isinstance(verify, bool) else False

    files = jdata.get('files', None)
 
    # 确保文件字段是元组格式
    if files and isinstance(files, dict):
        files = {
            key: (file_info['filename'], file_info['content'], file_info['content_type'])
            for key, file_info in files.items()
        }
    ret['files'] = None if not files else files
    # determine whether this is a POST or GET request
    if data:
        if not 'Content-Type' in headers:
            ret['data'] = data
            ret['method'] = 'POST'
            return ret
        if "application/json" in headers['Content-Type']:
            ret['method'] = 'JSON_POST'
            ret['data'] = data
        elif "multipart/form-data" in headers['Content-Type']:
            ret['method'] = 'UPLOAD'
            ret['data'] = data
        else:
            ret['data'] = data
            ret['method'] = 'POST'
    elif files:
        ret['method'] = 'UPLOAD'
    else:
        ret['method'] = 'GET'
    
    # return dictionary
    return ret


# 逐层读取文件夹中的多个json文件
def get_payloads_from_folder(folder_path,plain=False):
    # init
    payloads = []
    # read all files in the folder
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            logger.debug(TAG + "file: {}".format(file))
            if plain:
                if os.stat(os.path.join(root, file)).st_size == 0:
                    continue
                # get the full path of the file
                file_path = os.path.join(root, file)
                # get the formatted payload
                with open(file_path) as f:
                    payload = f.read()
                payloads.append(payload)
            else:
                if file.endswith('.json'):
                    # skip empty files
                    if os.stat(os.path.join(root, file)).st_size == 0:
                        continue
                    # get the full path of the file
                    file_path = os.path.join(root, file)
                    # get the formatted payload
                    payloads.append(get_unformatted_payload(file_path))

    # return payloads
    return payloads




def prowler_begin_to_sniff_payload(path,plain=False):
    # get payloads from folder
    if plain:
        payloads = get_payloads_from_folder(path,plain=True)
        logger.info(TAG + "payloads: {}".format(payloads))
        return payloads
    payloads = get_payloads_from_folder(path)
    payload_log_output = json.dumps(payloads, indent=4, ensure_ascii=False)
    logger.info(TAG + "payloads: {}".format(payload_log_output))
    return payloads


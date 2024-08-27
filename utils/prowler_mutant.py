from utils.logUtils import LoggerSingleton
from utils.dictUtils import content_types

logger = LoggerSingleton().get_logger()
TAG = "prowler_mutant.py: "


def mutant_methods_modify_content_type(headers, url, method, data, files):
    logger.info(TAG + "==>mutant_methods_modify_content_type")
    logger.debug(TAG + "==>headers: " + str(headers))
    mutant_payloads = []
    if 'Content-Type' in headers:
        for content_type in content_types:
            headers['Content-Type'] += ';' + content_type
            mutant_payloads.append({
                'headers': headers,
                'url': url,
                'method': method,
                'data': data,
                'files': files
            })
    return mutant_payloads

def mutant_methods_fake_content_type(headers,url,method,data,files):
    logger.info(TAG + "==>mutant_methods_fake_content_type")
    logger.debug(TAG + "==>headers: " + str(headers))
    mutant_payloads = []
    if 'Content-Type' in headers:
        for content_type in content_types:
            headers['Content-Type'] = content_type + ';'
            mutant_payloads.append({
                'headers': headers,
                'url': url,
                'method': method,
                'data': data,
                'files': files
            })

    return mutant_payloads

def mutant_upload_methods_double_equals(headers,url,method,data,files):
    logger.info(TAG + "==>mutant_upload_methods_double_equals")
    logger.debug(TAG + "==>headers: " + str(headers))
    if 'Content-Type' in headers:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    return headers,url,method,data,files


# 通用载荷变异方法
mutant_methods = [mutant_methods_modify_content_type, mutant_methods_fake_content_type]
# 上传载荷变异方法
mutant_methods_dedicated_to_upload = []

def prowler_begin_to_mutant_payloads(headers, url, method, data,files=None):
    logger.info(TAG + "==>begin to mutant payloads")
    mutant_payloads = []
    for mutant_method in mutant_methods:
        logger.info(TAG + "==>mutant method: " + str(mutant_method))
        sub_mutant_payloads = mutant_method(headers, url, method, data, files)
        mutant_payloads.extend(sub_mutant_payloads)
    if method == 'UPLOAD':
        for mutant_upload_method in mutant_methods_dedicated_to_upload:
            logger.info(TAG + "==>mutant upload method: " + str(mutant_upload_method))
            headers,url,method,data,files = mutant_upload_method(headers,url,method,data,files)
            mutant_payloads.append({
                'headers': headers,
                'url': url,
                'method': method,
                'data': data,
                'files': files
            })
    return mutant_payloads

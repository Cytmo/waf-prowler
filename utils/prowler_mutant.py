from utils.logUtils import LoggerSingleton
logger = LoggerSingleton().get_logger()
TAG = "prowler_mutant.py: "


def mutant_methods_modify_content_type(headers,url,method,data,files):
    logger.info(TAG + "==>mutant_methods_modify_content_type")
    logger.debug(TAG + "==>headers: " + str(headers))
    if 'Content-Type' in headers:
        headers['Content-Type'] += ';application/json'
    return headers,url,method,data,files

def mutant_methods_fake_content_type(headers,url,method,data,files):
    logger.info(TAG + "==>mutant_methods_fake_content_type")
    logger.debug(TAG + "==>headers: " + str(headers))
    if 'Content-Type' in headers:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    return headers,url,method,data,files

mutant_methods = [mutant_methods_modify_content_type,mutant_methods_fake_content_type]


def prowler_begin_to_mutant_payloads(headers, url, method, data,files):
    logger.info(TAG + "==>begin to mutant payloads")
    mutant_payloads = []
    for mutant_method in mutant_methods:
        logger.info(TAG + "==>mutant method: " + str(mutant_method))
        headers,url,method,data,files = mutant_method(headers,url,method,data,files)
        mutant_payloads.append({
            'headers': headers,
            'url': url,
            'method': method,
            'data': data,
            'files': files
        })
    return mutant_payloads  


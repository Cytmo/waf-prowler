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


# change content-type to dict of content-type
def mutant_methods_change_content_type(headers, url, method, data, files):
    logger.info(TAG + "==>mutant_methods_modify_content_type")
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


mutant_methods = [mutant_methods_modify_content_type, mutant_methods_change_content_type]


def prowler_begin_to_mutant_payloads(headers, url, method, data, files):
    logger.info(TAG + "==>begin to mutant payloads")
    mutant_payloads = []
    for mutant_method in mutant_methods:
        logger.info(TAG + "==>mutant method: " + str(mutant_method))
        sub_mutant_payloads = mutant_method(headers, url, method, data, files)
        mutant_payloads.extend(sub_mutant_payloads)
    return mutant_payloads

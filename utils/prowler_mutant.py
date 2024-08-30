import random

import urllib.parse
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

def random_case_switch(text):
    return ''.join([c.upper() if random.choice([True, False]) else c.lower() for c in text])


def mutant_methods_case_switching(headers, url, method, data, files):
    logger.info(TAG + "==>mutant_methods_case_switching")
    logger.debug(TAG + "==>headers: " + str(headers))

    # Create a list to hold the mutated payloads
    mutant_payloads = []

    # Apply random case switching to the URL
    # mutated_url = random_case_switch(url)
    # don't mutate the url
    mutated_url = url
    # Apply random case switching to the data if it's a string
    mutated_data = data
    if isinstance(data, str):
        mutated_data = random_case_switch(data)

    # Apply random case switching to file names if present
    mutated_files = files
    if files:
        mutated_files = {name: (random_case_switch(filename), file) for name, (filename, file) in files.items()}

    # Create the mutated payload
    mutant_payloads.append({
        'headers': headers,
        'url': mutated_url,
        'method': method,
        'data': mutated_data,
        'files': mutated_files
    })

    return mutant_payloads

def url_encode_payload(payload):
    """Helper function to URL encode a given payload."""
    return urllib.parse.quote(payload, safe='/:&?=')

def mutant_methods_url_encoding(headers, url, method, data, files):
    logger.info(TAG + "==>mutant_methods_url_encoding")
    logger.debug(TAG + "==>headers: " + str(headers))

    # Create a list to hold the mutated payloads
    mutant_payloads = []

    # URL encode only the query parameters or other parts of the URL
    # Split the URL into components and encode them properly
    parsed_url = urllib.parse.urlparse(url)
    encoded_query = urllib.parse.quote(parsed_url.query, safe='=&')
    encoded_path = urllib.parse.quote(parsed_url.path, safe='/')
    mutated_url = urllib.parse.urlunparse(parsed_url._replace(path=encoded_path, query=encoded_query))
    
    # URL encode the data if it's a string
    mutated_data = data
    if isinstance(data, str):
        mutated_data = url_encode_payload(data)

    # URL encode file names if present
    mutated_files = files
    if files:
        mutated_files = {name: (url_encode_payload(filename), file) for name, (filename, file) in files.items()}

    # Create the mutated payload
    mutant_payloads.append({
        'headers': headers,
        'url': mutated_url,
        'method': method,
        'data': mutated_data,
        'files': mutated_files
    })

    return mutant_payloads


def mutant_upload_methods_double_equals(headers,url,method,data,files):
    logger.info(TAG + "==>mutant_upload_methods_double_equals")
    logger.debug(TAG + "==>headers: " + str(headers))
    mutant_payloads = []
    if 'filename' in files:
        files['filename'] = files['filename'] + "="
        mutant_payloads.append({
            'headers': headers,
            'url': url,
            'method': method,
            'data': data,
            'files': files
        })
    return mutant_payloads

def unicode_obfuscate(text):
    """Helper function to encode ASCII characters into their Unicode equivalent."""
    obfuscated_text = ""
    for char in text:
        if random.choice([True, False]):
            # 50% chance to obfuscate each character
            obfuscated_text += '\\u{:04x}'.format(ord(char))
        else:
            obfuscated_text += char
    return obfuscated_text

def mutant_methods_unicode_normalization(headers, url, method, data, files):
    logger.info(TAG + "==>mutant_methods_unicode_normalization")
    logger.debug(TAG + "==>headers: " + str(headers))

    mutant_payloads = []

    # Apply Unicode obfuscation to URL path and query
    parsed_url = urllib.parse.urlparse(url)
    obfuscated_path = unicode_obfuscate(parsed_url.path)
    obfuscated_query = unicode_obfuscate(parsed_url.query)
    mutated_url = urllib.parse.urlunparse(parsed_url._replace(path=obfuscated_path, query=obfuscated_query))

    # Apply Unicode obfuscation to the data if it's a string
    mutated_data = data
    if isinstance(data, str):
        mutated_data = unicode_obfuscate(data)

    # Apply Unicode obfuscation to file names if present
    mutated_files = files
    if files:
        mutated_files = {name: (unicode_obfuscate(filename), file) for name, (filename, file) in files.items()}

    # Create the mutated payload
    mutant_payloads.append({
        'headers': headers,
        'url': mutated_url,
        'method': method,
        'data': mutated_data,
        'files': mutated_files
    })

    return mutant_payloads
def insert_line_breaks(text):
    """Helper function to insert CR/LF characters randomly in the text."""
    obfuscated_text = ""
    for char in text:
        if random.choice([True, False]):
            obfuscated_text += '%0A'  # LF (Line Feed)
        obfuscated_text += char
    return obfuscated_text

def mutant_methods_line_breaks(headers, url, method, data, files):
    logger.info(TAG + "==>mutant_methods_line_breaks")
    logger.debug(TAG + "==>headers: " + str(headers))

    mutant_payloads = []

    # Apply line breaks to URL path and query
    parsed_url = urllib.parse.urlparse(url)
    obfuscated_path = insert_line_breaks(parsed_url.path)
    obfuscated_query = insert_line_breaks(parsed_url.query)
    mutated_url = urllib.parse.urlunparse(parsed_url._replace(path=obfuscated_path, query=obfuscated_query))

    # Apply line breaks to the data if it's a string
    mutated_data = data
    if isinstance(data, str):
        mutated_data = insert_line_breaks(data)

    # Apply line breaks to file names if present
    mutated_files = files
    if files:
        mutated_files = {name: (insert_line_breaks(filename), file) for name, (filename, file) in files.items()}

    # Create the mutated payload
    mutant_payloads.append({
        'headers': headers,
        'url': mutated_url,
        'method': method,
        'data': mutated_data,
        'files': mutated_files
    })

    return mutant_payloads

# 通用载荷变异方法开关
mutant_methods_enabled = {
    "mutant_methods_modify_content_type": True,
    "mutant_methods_fake_content_type": True,
    "mutant_methods_case_switching": False,
    "mutant_methods_url_encoding": True,
    "mutant_methods_unicode_normalization": False,
    "mutant_methods_line_breaks": True
}

# 所有变异方法的字典
all_mutant_methods = {
    "mutant_methods_modify_content_type": mutant_methods_modify_content_type,
    "mutant_methods_fake_content_type": mutant_methods_fake_content_type,
    "mutant_methods_case_switching": mutant_methods_case_switching,
    "mutant_methods_url_encoding": mutant_methods_url_encoding,
    "mutant_methods_unicode_normalization": mutant_methods_unicode_normalization,
    "mutant_methods_line_breaks": mutant_methods_line_breaks
}

# 初始化启用的变异方法
mutant_methods = [
    method for name, method in all_mutant_methods.items() 
    if mutant_methods_enabled.get(name, False)
]

# 通用载荷变异方法
mutant_methods = [mutant_methods_modify_content_type, mutant_methods_fake_content_type, mutant_methods_case_switching,
                  mutant_methods_url_encoding, mutant_methods_unicode_normalization, mutant_methods_line_breaks]
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
    # keep original url for result
    for payload in mutant_payloads:
        payload['original_url'] = url
    return mutant_payloads

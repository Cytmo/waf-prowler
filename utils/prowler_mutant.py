import json
import random
import re
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
    # else:
    #     for content_type in content_types:
    #         headers['Content-Type'] =  ';'+content_type + ';'
    #         mutant_payloads.append({
    #             'headers': headers,
    #             'url': url,
    #             'method': method,
    #             'data': data,
    #             'files': files
    #         })        
    return mutant_payloads

# 协议未覆盖绕过
# 在 http 头里的 Content-Type 提交表单支持四种协议：
# •application/x-www-form-urlencoded -编码模式
# •multipart/form-data -文件上传模式
# •text/plain -文本模式
# •application/json -json模式
# 文件头的属性是传输前对提交的数据进行编码发送到服务器。其中 multipart/form-data 
# 表示该数据被编码为一条消息,页上的每个控件对应消息中的一个部分。所以，当 waf 没有规则匹配该协议传输的数据时可被绕过。
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


def random_case(text):
    """Randomly changes the case of each character in the text."""
    return ''.join([c.upper() if random.choice([True, False]) else c.lower() for c in text])

def insert_comments(text):
    """Insert random comments or spaces in the text to break up keywords."""
    parts = list(text)
    for i in range(1, len(parts) - 1):
        if random.choice([True, False]):
            parts[i] = '/*' + parts[i] + '*/'
    return ''.join(parts)

def mutant_methods_case_and_comment_obfuscation(headers, url, method, data, files):
    logger.info(TAG + "==>mutant_methods_case_and_comment_obfuscation")
    logger.debug(TAG + "==>headers: " + str(headers))

    mutant_payloads = []

    # Apply random case and comment obfuscation to the URL
    parsed_url = urllib.parse.urlparse(url)
    obfuscated_path = random_case(insert_comments(parsed_url.path))
    obfuscated_query = random_case(insert_comments(parsed_url.query))
    mutated_url = urllib.parse.urlunparse(parsed_url._replace(path=obfuscated_path, query=obfuscated_query))

    # Apply the same to data if it's a string
    mutated_data = data
    if isinstance(data, str):
        mutated_data = random_case(insert_comments(data))

    # Apply the same to file names if present
    mutated_files = files
    if files:
        mutated_files = {name: (random_case(insert_comments(filename)), file) for name, (filename, file) in files.items()}

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
    # 只有 multipart/form-data 才需要可以使用这个方法
    content_type = headers.get('Content-Type')
    if content_type and re.match('multipart/form-data', content_type) or 'filename' in str(data):
        # 双写等号：如果含有filename，则替换为filename=
        data_str = data.decode()
        if 'filename' in data_str:
            data_str = data_str.replace('filename', 'filename=')
            mutant_payloads.append({
                        'headers': headers,
                        'url': url,
                        'method': method,
                        'data': data_str
                    })
    # if files:
    #     if 'filename' in files:
    #         files['filename'] = files['filename'] + "="
    #         mutant_payloads.append({
    #             'headers': headers,
    #             'url': url,
    #             'method': method,
    #             'data': data,
    #             'files': files
    #         })

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

def mutant_methods_for_test_use(headers, url, method, data, files):
    logger.info(TAG + "==>mutant_methods_for_test_use")
    # logger.debug(TAG + "==>headers: " + str(headers))

    mutant_payloads = []
    if data:
        print(data)
        # replace cmd to c%0Amd in data
        data = data.replace('cmd', 'c%0Amd')
        data = data.replace('passwd', 'passw%0Ad')
        data = data.replace('SELECT','se/*comment*/lect')
        print(data)

        # exit()
    url = url.replace('cmd', 'c%0Amd')
    url = url.replace('SELECT','se/*comment*/lect')
    url = url.replace('passwd', 'passw%0Ad')
    print(url)
    mutant_payloads.append({
        'headers': headers,
        'url': url,
        'method': method,
        'data': data,
        'files': files
    })
    logger.debug(TAG + "==>mutant_payloads: " + str(mutant_payloads))
    return mutant_payloads


def mutant_methods_multipart_boundary(headers, url, method, data, files):
    """ 对 boundary 进行变异进而绕过"""
    logger.info(TAG + "==>mutant_methods_multipart_boundary")
    logger.debug(TAG + "==>headers: " + str(headers))
    # 只有 multipart/form-data 才需要可以使用这个方法
    content_type = headers.get('Content-Type')
    if not content_type or not re.match('multipart/form-data', content_type):
        if not 'filename' in str(data):
            return []

    # 解析filename
    data_str = data.decode()
    pattern = re.compile(r'Content-Disposition: form-data;.*filename="([^"]+)"')
    filenames = pattern.findall(data_str)

    # 从Content-Type中解析boundary的正则表达式
    pattern = re.compile(r'boundary=(.*)')
    match = pattern.search(content_type)
    if match:
        boundary = match.group(1)
        print(f"Found boundary: {boundary}")
    else:
        # 无boundary
        return []

    # 拼接后为----realBoundary
    boundary0 = '----real'
    boundary1 = 'Boundary'
    mutant_payloads = []
    # 基于 RFC 2231 的boundary构造
    content_type += f'; boundary*0={boundary0}; boundary*1={boundary1}'

    # 构造新的header
    headers.update({'Content-Type': content_type})
    # 构造请求体，第一种是go的解析方式，第二种是flask的解析方式
    # waf解析的边界
    fake_body = f'--{boundary}\r\n'
    fake_body += f'Content-Disposition: form-data; name="field1"\r\n\r\n'
    fake_body += f'fake data\r\n'
    fake_body += f'--{boundary}--\r\n'

    # 真正的源站解析的边界
    real_body = ['', '']
    for filename in filenames:
        real_body[0] += f'--{boundary0}{boundary1}\r\n'
        real_body[0] += f'Content-Disposition: form-data; name="field2"; filename="{filename}"\r\n'
        real_body[0] += f'Content-Type: text/plain\r\n\r\n'
        real_body[0] += f'real data\r\n'
    real_body[0] += f'--{boundary0}{boundary1}--\r\n'

    for filename in filenames:
        real_body[1] += f'--{boundary}{boundary0}{boundary1}\r\n'
        real_body[1] += f'Content-Disposition: form-data; name="field2"; filename="{filename}"\r\n'
        real_body[1] += f'Content-Type: text/plain\r\n\r\n'
        real_body[1] += f'real data\r\n'
    real_body[1] += f'--{boundary}{boundary0}{boundary1}--\r\n'

    for body in real_body:
        mutant_payloads.append({
            'headers': headers,
            'url': url,
            'method': method,
            'data': data_str+body
        })
    return mutant_payloads

# 资源限制角度绕过WAF
# 超大数据包绕过
# 这是众所周知、而又难以解决的问题。如果HTTP请求POST BODY太大，检测所有的内容，WAF集群消耗太大的CPU、内存资源。因此许多WAF只检测前面的
# 几K字节、1M、或2M。对于攻击者而然，只需要在POST BODY前面添加许多无用数据，把攻击payload放在最后即可绕过WAF检测。
def mutant_methods_add_padding(headers, url, method, data, files):
    """ 绕过WAF的超大数据包检测"""
    logger.info(TAG + "==>mutant_methods_add_padding")
    logger.debug(TAG + "==>headers: " + str(headers))
    mutant_payloads = []
    padding_data = 'x' * 1024  * 5  # 5 kB 的无用数据
    if isinstance(data, bytes) and isinstance(padding_data, str):
        padding_data = padding_data.encode()  # 将 padding_data 转换为字节串
    if data:
        data += padding_data
    else:
        data = padding_data
    mutant_payloads.append({
        'headers': headers,
        'url': url,
        'method': method,
        'data': data,
        'files': files
    })
    return mutant_payloads


# 删除data中的Content-Type
def mutant_methods_delete_content_type_of_data(headers, url, method, data, files):
    """ 删除data中的Content-Type:xxx; """
    logger.info(TAG + "==>mutant_methods_delete_content_type_of_data")
    logger.debug(TAG + "==>headers: " + str(headers))
    mutant_payloads = []
    # 只有 multipart/form-data 才需要可以使用这个方法
    content_type = headers.get('Content-Type')
    if content_type and re.match('multipart/form-data', content_type):
        pattern = r'Content-Type:[^;]+;\s*'
        # 使用re.sub()函数来删除所有匹配的部分
        data_str = data.decode()
        cleaned_data = re.sub(pattern, '', data_str)
        mutant_payloads.append({
            'headers': headers,
            'url': url,
            'method': method,
            'data': cleaned_data
        })
    return mutant_payloads


'''
ALL MUTANT METHODS:
mutant_methods_modify_content_type
mutant_methods_fake_content_type
mutant_methods_case_switching
mutant_methods_url_encoding
mutant_methods_unicode_normalization
mutant_methods_line_breaks
mutant_methods_add_padding
mutant_methods_multipart_boundary
mutant_upload_methods_double_equals

'''
# 为变异方法添加开关
mutant_methods_config = {
    "mutant_methods_modify_content_type": (mutant_methods_modify_content_type, True),
    "mutant_methods_fake_content_type": (mutant_methods_fake_content_type, True),
    "mutant_methods_case_and_comment_obfuscation": (mutant_methods_case_and_comment_obfuscation, False),
    "mutant_methods_url_encoding": (mutant_methods_url_encoding, True),
    "mutant_methods_unicode_normalization": (mutant_methods_unicode_normalization, False),
    "mutant_methods_line_breaks": (mutant_methods_line_breaks, True),
    "mutant_methods_add_padding": (mutant_methods_add_padding, True),
    "mutant_methods_multipart_boundary": (mutant_methods_multipart_boundary, True),
    "mutant_upload_methods_double_equals": (mutant_upload_methods_double_equals, True),
    "mutant_methods_delete_content_type_of_data": (mutant_methods_delete_content_type_of_data, True)
}

# 初始化启用的变异方法
mutant_methods = [
    method for method, enabled in mutant_methods_config.values()
    if enabled
]
# mutant_methods = [
# 上传载荷变异方法
mutant_methods_dedicated_to_upload = []

def prowler_begin_to_mutant_payloads(headers, url, method, data,files=None):
    logger.info(TAG + "==>begin to mutant payloads")
    mutant_payloads = []
    for mutant_method in mutant_methods:
        logger.info(TAG + "==>mutant method: " + str(mutant_method))
        sub_mutant_payloads = mutant_method(headers, url, method, data, files)
        # 如果没有子变异载荷，输出警告
        if not sub_mutant_payloads:
            logger.warning(TAG + "==>no sub mutant payloads for method: " + str(mutant_method))
        for sub_mutant_payload in sub_mutant_payloads:
            sub_mutant_payload['mutant_method'] = mutant_method.__name__
        mutant_payloads.extend(sub_mutant_payloads)

    if method == 'UPLOAD':
        for mutant_upload_method in mutant_methods_dedicated_to_upload:
            logger.info(TAG + "==>mutant upload method: " + str(mutant_upload_method))
            headers,url,method,data,files = mutant_upload_method(headers,url,method,data,files=data)
            mutant_payloads.append({
                'headers': headers,
                'url': url,
                'method': method,
                'data': data,
                'files': data
            })
    # keep original url for result
    for payload in mutant_payloads:
        payload['original_url'] = url
    return mutant_payloads

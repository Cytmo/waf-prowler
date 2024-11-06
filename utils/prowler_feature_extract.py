import json
import os
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Union

if __name__ == "__main__":
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__), '../'))

from utils.logUtils import LoggerSingleton
from utils.dictUtils import content_types

# Logger
logger = LoggerSingleton().get_logger()

TAG = "prolwer_feature_extract.py "
from sklearn.feature_extraction.text import TfidfVectorizer
fixed_length = 10
def dict_to_fixed_length_tfidf_vector(data_dict, fixed_length=fixed_length):
    # 创建TfidfVectorizer对象
    vectorizer = TfidfVectorizer()
    data_dict = str(data_dict)
    # 将JSON字符串转化为TF-IDF特征向量
    tfidf_vector = vectorizer.fit_transform([data_dict]).toarray()
    
    # 获取特征名称
    feature_names = vectorizer.get_feature_names_out()
    
    # 如果特征数量小于固定长度，进行填充
    if tfidf_vector.shape[1] < fixed_length:
        padded_vector = np.pad(tfidf_vector, ((0, 0), (0, fixed_length - tfidf_vector.shape[1])), mode='constant')
    else:
        # 选择前fixed_length个特征（根据TF-IDF值的重要性进行选择）
        important_features = np.argsort(-tfidf_vector.sum(axis=0))[:fixed_length]
        padded_vector = tfidf_vector[:, important_features]

    return padded_vector
def extract_url_features(url: str) -> List[int]:
    parsed_url = urlparse(url)
    sql_keywords = {'SELECT', 'UNION', 'DROP', 'password'}

    url_length = len(url)
    param_count = len(parse_qs(parsed_url.query))
    path_depth = len(parsed_url.path.split('/'))
    special_chars_count = len(re.findall(r'%20|=|&', url))
    sql_keyword_count = sum(keyword in url.upper() for keyword in sql_keywords)
    protocol = int(parsed_url.scheme == 'https')  # 1 for HTTPS, 0 for HTTP
    subdomain_count = len(parsed_url.netloc.split('.')) - 1  # 计算子域名数量
    domain_length = len(parsed_url.netloc)  # 域名长度

    return [url_length, param_count, path_depth, special_chars_count, sql_keyword_count, protocol, subdomain_count, domain_length]

def extract_method_feature(method: str) -> int:
    method_dict = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}
    return method_dict.get(method, -1)

def extract_header_features(headers: Dict[str, str]) -> List[int]:
    header_keys = {"Host", "User-Agent", "Content-Type", "Accept"}
    header_count = len(headers)
    user_agent_length = len(headers.get("User-Agent", ""))
    suspicious_content_type = int('application/x-www-form-urlencoded' in headers.get("Content-Type", ""))
    custom_header_count = sum(1 for key in headers if key not in header_keys)  # 自定义头部数量
    content_length = int(headers.get("Content-Length", 0))  # 内容长度
    return [header_count, custom_header_count, content_length] + [int(key in headers) for key in header_keys] + [user_agent_length, suspicious_content_type]

def extract_body_features(body: Union[str, Dict[str, Any]]) -> List[int]:
    sql_keywords = {'SELECT', 'UNION', 'DROP', 'password'}
    special_char_count = sum(int(char in str(body)) for char in ["'", '"', "--", ";"])

    if isinstance(body, str):
        body_length = len(body)
        body_sql_keyword_count = sum(keyword in body for keyword in sql_keywords)
    elif isinstance(body, dict):
        body_content = " ".join(
            str(v["content"]) if isinstance(v, dict) and "content" in v else str(v)
            for v in body.values()
        )
        body_length = len(body_content)
        body_sql_keyword_count = sum(keyword in body_content for keyword in sql_keywords)
    else:
        body_length = 0
        body_sql_keyword_count = 0

    return [body_length, body_sql_keyword_count, special_char_count]
from sklearn.feature_extraction.text import TfidfVectorizer

def extract_text_features_tfidf(body: Union[str, Dict[str, Any]], vectorizer: TfidfVectorizer) -> np.ndarray:
    # 如果 body 是字典，处理字典的内容
    if isinstance(body, dict):
        body_content = " ".join(
            str(v["content"]) if isinstance(v, dict) and "content" in v else str(v)
            for v in body.values()
        )
    else:
        body_content = str(body)

    # 使用TF-IDF提取特征
    tfidf_matrix = vectorizer.transform([body_content])
    return tfidf_matrix.toarray()[0]  # 返回一维数组

def extract_text_features(body: Union[str, Dict[str, Any]]) -> List[int]:
    suspicious_terms = ['SELECT', 'DROP', 'INSERT', 'DELETE', 'UNION']

    # 如果 body 是字典，处理字典的内容
    if isinstance(body, dict):
        body_content = " ".join(
            str(v["content"]) if isinstance(v, dict) and "content" in v else str(v)
            for v in body.values()
        )
    else:
        # 如果 body 不是字典，直接将其转换为字符串
        body_content = str(body)

    term_counts = [body_content.lower().count(term.lower()) for term in suspicious_terms]

    return term_counts

def extract_features(request: Dict[str, Any]) -> np.ndarray:
    logger.info(TAG + "payload: " + str(request))
    
    url_features = extract_url_features(request["url"])
    method_feature = extract_method_feature(request["method"])
    header_features = extract_header_features(request["headers"])
    body_features = extract_body_features(request.get("body", ""))
    text_features = extract_text_features(request.get("body", ""))
    # 创建TF-IDF向量化器
    url_feature_vector = dict_to_fixed_length_tfidf_vector({"url": request["url"]})
    body_feature_vector = dict_to_fixed_length_tfidf_vector({"body": request.get("body", "")})
    # 添加各个子部分的TF-IDF特征
    method_feature_vector = dict_to_fixed_length_tfidf_vector({"method": request["method"]})
    header_feature_vector = dict_to_fixed_length_tfidf_vector({"headers": request["headers"]})
    if request.get("body", "") is None:
        length_of_body = 0
    else:
        length_of_body = len(request.get("body", ""))
    # 添加各个子部分的长度信息
    lengths = [
        len(request["url"]),  # URL长度
        len(request["method"]),  # 方法长度
        len(request["headers"]),  # 头部长度
        length_of_body  # 主体长度
    ]
    # print(url_feature_vector[0].tolist())
    # print(body_feature_vector[0].tolist())
    # print(method_feature[0].tolist())
    # print(header_feature[0].tolist())
    features = url_features + [method_feature] + header_features + body_features + text_features+lengths\
                + url_feature_vector[0].tolist() + body_feature_vector[0].tolist() + method_feature_vector[0].tolist() + header_feature_vector[0].tolist()
    # print(features)
    return np.array(features)

def prowler_feature_extract(request: Dict[str, Any]) -> np.ndarray:
    return extract_features(request)

if __name__ == "__main__":
    # 示例请求字典
    http_request = {
        "url": "http://localhost:8003/upload",
        "method": "POST",
        "headers": {
            "Host": "localhost:8003",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "Origin": "http://localhost:8003",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Referer": "http://localhost:8003/",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7",
            "Connection": "close"
        },
        "body": "SELECT * FROM users WHERE id = 1"  # 示例主体
    }

    # 提取特征向量
    feature_vector = extract_features(http_request)

    # 特征描述
    feature_descriptions = [
        "URL Length", "Parameter Count", "Path Depth", "Special Characters Count",
        "SQL Keyword Count", "Protocol (HTTPS)", "Subdomain Count", "Domain Length",
        "Method Encoded", "Header Count", "Custom Header Count", "Content Length",
        "Header (Host)", "Header (User-Agent)", "Header (Content-Type)", 
        "Header (Accept)", "User-Agent Length", "Suspicious Content-Type",
        "Body Length", "Body SQL Keyword Count", "Special Char Count",
        "Term Count (SELECT)", "Term Count (DROP)", "Term Count (INSERT)", 
        "Term Count (DELETE)", "Term Count (UNION)", "URL Length", "Method Length",
        "Header Length", "Body Length",
    ]

    # 打印特征向量及其目的
    print("固定长度特征向量:", feature_vector)
    for desc, value in zip(feature_descriptions, feature_vector):
        print(f"{desc}: {value}")
    # "URL TF-IDF", "Body TF-IDF", "Method TF-IDF" "Header TF-IDF" have length of 10
    for i in range(10):
        print(f"URL TF-IDF {i}: {feature_vector[30 + i]}")
    for i in range(10):
        print(f"Body TF-IDF {i}: {feature_vector[40 + i]}")
    for i in range(10):
        print(f"Method TF-IDF {i}: {feature_vector[50 + i]}")
    for i in range(10):
        print(f"Header TF-IDF {i}: {feature_vector[60 + i]}")
    print("特征向量长度:", len(feature_vector))

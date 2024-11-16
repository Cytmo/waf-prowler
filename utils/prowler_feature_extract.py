import json
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Union

from sklearn.feature_extraction.text import HashingVectorizer

# 定义常量
TAG = "prowler_feature_extract.py"

# 定义特征提取类
class FeatureExtractor:
    def __init__(self):
        # 增加 URL 特征维度，并使用字符级 n-gram
        self.url_fixed_length = 50
        self.body_fixed_length = 20
        self.header_fixed_length = 5  # 保持 Header 特征维度不变

        # 初始化 HashingVectorizer 实例
        self.url_vectorizer = HashingVectorizer(
            n_features=self.url_fixed_length,
            alternate_sign=False,
            norm=None,
            analyzer='char_wb',
            ngram_range=(3, 5)
        )
        self.body_vectorizer = HashingVectorizer(
            n_features=self.body_fixed_length,
            alternate_sign=False,
            norm=None,
            analyzer='word',
            ngram_range=(1, 2)
        )
        self.header_vectorizer = HashingVectorizer(
            n_features=self.header_fixed_length,
            alternate_sign=False,
            norm=None,
            analyzer='word',
            ngram_range=(1, 2)
        )

        # 定义支持的 HTTP 方法列表，用于整数编码
        self.methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE", "CONNECT"]
        self.method_dict = {method: idx for idx, method in enumerate(self.methods)}
    
    def extract_url_features(self, url: str) -> List[float]:
        parsed_url = urlparse(url)
        sql_keywords = {'SELECT', 'UNION', 'DROP', 'password'}

        url_length = len(url)
        param_count = len(parse_qs(parsed_url.query))
        path_depth = len(parsed_url.path.strip('/').split('/')) if parsed_url.path else 0
        special_chars_count = len(re.findall(r'%20|=|&|\?|%', url))
        sql_keyword_count = sum(keyword in url.upper() for keyword in sql_keywords)
        protocol = int(parsed_url.scheme.lower() == 'https')  # 1 表示 HTTPS，0 表示 HTTP
        subdomain_count = len(parsed_url.netloc.split('.')) - 2 if '.' in parsed_url.netloc else 0  # 子域名数量
        domain_length = len(parsed_url.netloc)  # 域名长度

        numerical_features = [
            url_length, param_count, path_depth,
            special_chars_count, sql_keyword_count,
            protocol, subdomain_count, domain_length
        ]

        # 使用字符级 HashingVectorizer 处理 URL 文本
        url_text_features = self.url_vectorizer.transform([url]).toarray()[0]

        return numerical_features + url_text_features.tolist()

    def extract_method_feature(self, method: str) -> List[float]:
        # 将 HTTP 方法映射为整数编码
        method_encoded = [self.method_dict.get(method.upper(), -1)]
        return method_encoded

    def extract_header_features(self, headers: Dict[str, str]) -> List[float]:
        header_keys = {"Host", "User-Agent", "Content-Type", "Accept"}
        header_count = len(headers)
        user_agent_length = len(headers.get("User-Agent", ""))
        suspicious_content_type = int('application/x-www-form-urlencoded' in headers.get("Content-Type", ""))
        custom_header_count = sum(1 for key in headers if key not in header_keys)  # 自定义头部数量
        content_length = int(headers.get("Content-Length", 0))  # 内容长度

        numerical_features = [
            header_count, custom_header_count, content_length,
            user_agent_length, suspicious_content_type
        ]

        # 头部字段的存在性（二进制特征）
        header_presence = [int(key in headers) for key in header_keys]

        # 使用 HashingVectorizer 处理头部文本
        header_str = ' '.join([f"{k}: {v}" for k, v in headers.items()])
        header_text_features = self.header_vectorizer.transform([header_str]).toarray()[0]

        return numerical_features + header_presence + header_text_features.tolist()

    def extract_body_features(self, body: Union[str, Dict[str, Any]]) -> List[float]:
        sql_keywords = {'SELECT', 'UNION', 'DROP', 'password'}
        special_chars = ["'", '"', "--", ";"]

        if isinstance(body, dict):
            body_content = " ".join(
                str(v.get("content", v)) if isinstance(v, dict) else str(v)
                for v in body.values()
            )
        else:
            body_content = str(body)

        body_length = len(body_content)
        body_sql_keyword_count = sum(body_content.upper().count(keyword) for keyword in sql_keywords)
        special_char_count = sum(body_content.count(char) for char in special_chars)

        numerical_features = [body_length, body_sql_keyword_count, special_char_count]

        # 使用 HashingVectorizer 处理主体文本
        body_text_features = self.body_vectorizer.transform([body_content]).toarray()[0]

        return numerical_features + body_text_features.tolist()

    def extract_features(self, request: Dict[str, Any]) -> np.ndarray:
        # 提取各部分特征
        url = request.get("url", "")
        method = request.get("method", "")
        headers = request.get("headers", {})
        body = request.get("body", "")

        url_features = self.extract_url_features(url)
        method_features = self.extract_method_feature(method)
        header_features = self.extract_header_features(headers)
        body_features = self.extract_body_features(body)

        # 合并所有特征为一个向量
        features = url_features + method_features + header_features + body_features

        return np.array(features)

# 提供给外部调用的特征提取函数
def prowler_feature_extract(request: Dict[str, Any]) -> np.ndarray:
    extractor = FeatureExtractor()
    return extractor.extract_features(request)

# 示例使用
if __name__ == "__main__":
    # 示例请求字典
    http_request_1 = {
        "url": "http://localhost:8003/UPload?file=1.php",
        "method": "POST",
        "headers": {
            "Host": "localhost:8003",
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html",
        },
        "body": {
            "username": "admin",
            "password": "password' OR '1'='1"
        },
    }

    http_request_2 = {
        "url": "http://localhost:8003/upload?file=1.php",  # 端口从8003变为8004
        "method": "POST",
        "headers": {
            "Host": "localhost:8003",
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html",
        },
        "body": {
            "username": "admin",
            "password": "password' OR '1'='1"
        },
    }

    # 初始化特征提取器
    extractor = FeatureExtractor()

    # 提取特征向量
    feature_vector_1 = extractor.extract_features(http_request_1)
    feature_vector_2 = extractor.extract_features(http_request_2)

    # 打印特征向量及其长度
    print("请求 1 特征向量长度:", len(feature_vector_1))
    print("请求 2 特征向量长度:", len(feature_vector_2))

    print("请求 1 特征向量:", feature_vector_1)
    print("请求 2 特征向量:", feature_vector_2)
    # 计算两个特征向量的差异
    difference = np.abs(feature_vector_1 - feature_vector_2)
    print("特征向量差异:", difference)
    print("非零差异的特征数:", np.count_nonzero(difference))

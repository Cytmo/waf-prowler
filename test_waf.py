import re

# 定义正则表达式
rce_regex = re.compile(r'\b(net|shell|cmd|exec|spawn|popen|passthru|system|proc_open|wget|curl|passwd|socket_connect|open_basedir|disable_functions|file_get_contents|file_put_contents|copy|move|rename|delete|shell_exec)\b', re.IGNORECASE)
sql_injection_regex = re.compile(r'\b(select|update|delete|insert|replace|truncate|create|drop|union|exec|sp_exec|xp_cmdshell|call)\s+', re.IGNORECASE)

print("Please input test string for waf:")
test_string_rce = input("RCE Test String: ")
test_string_sql = input("SQL Injection Test String: ")


# 测试 RCE 正则表达式
rce_match = rce_regex.search(test_string_rce)
if rce_match:
    print("RCE Regex matched:", rce_match.group())

# 测试 SQL Injection 正则表达式
sql_match = sql_injection_regex.search(test_string_sql)
if sql_match:
    print("SQL Injection Regex matched:", sql_match.group())

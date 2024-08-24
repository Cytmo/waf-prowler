import requests

def send_get_request(headers, url):
    response = requests.get(url, headers=headers, verify=False)
    return response

def send_post_request(headers, data, url):
    response = requests.post(url, headers=headers, data=data, verify=False)
    return response

def send_json_post_request(headers, json_data, url):
    response = requests.post(url, headers=headers, json=json_data, verify=False)
    return response

def send_upload_file_request(headers, files, url):
    response = requests.post(url, headers=headers, files=files, verify=False)
    return response
import base64

import requests

# Gitee仓库信息
username = 'jksjldggz'
repo_name = 'type'
path = '/'
file_name = 'test.txt'

# 访问令牌（token）用于验证身份
access_token = 'd2006e527547b9483406cf7d5d559055'


# 检查文件是否已经存在于gitee仓库，存在的话删除旧数据
def removeIfExist(username, repo_name, path, access_token, file_name):
    url = f'https://gitee.com/api/v5/repos/{username}/{repo_name}/contents/{path}'
    headers = {'Authorization': f'token {access_token}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        files = response.json()
        for file in files:
            if file['name'] == file_name:
                # Delete the existing file
                url = file['url']
                sha = file['sha']
                message = 'Delete existing file'
                data = {'message': message, 'sha': sha}
                response = requests.delete(url, headers=headers, json=data)
                if response.status_code != 204:
                    print(f'Failed to delete file. Status code: {response.status_code}')
                else:
                    print('Existing file deleted successfully.')


# 上传新文件到gitee
def uploadNewFileToGitee(username, repo_name, path, access_token, file_name):
    # 读取要上传的文件内容（bytes比特流）
    with open('/AEN.txt', 'rb') as f:
        file_content = f.read()
    # 构建API请求URL和headers
    url = f'https://gitee.com/api/v5/repos/{username}/{repo_name}/contents/{path}/{file_name}'
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': f'token {access_token}',
    }
    # 构建POST请求数据
    data = {
        'message': 'Upload a file',
        'content': base64.b64encode(file_content).decode('utf-8'),
    }
    # 发送POST请求
    response = requests.post(url, headers=headers, json=data)
    # 处理响应结果
    if response.status_code == 201:
        print('File uploaded successfully!')
    else:
        print(f'Failed to upload file. Status code: {response.status_code}')


# def updateFileToGitee(username, repo_name, path, access_token, file_name):
#     # 获取原有文件的SHA哈希值
#     get_url = f'https://gitee.com/api/v5/repos/{username}/{repo_name}/contents{path}{file_name}'
#     headers = {'Authorization': f'token {access_token}'}
#     response = requests.get(get_url, headers=headers)
#     response_json = response.json()
#     original_sha = response_json['sha']
#
#     # 读取要上传的文件内容（bytes比特流）
#     with open('/AEN.txt', 'rb') as f:
#         file_content = f.read()
#     # 准备提交更新的数据
#     data = {
#         "message": "Updated file",
#         "content": base64.b64encode(file_content).decode('utf-8'),  # base64编码的bytes文件
#         "sha": original_sha
#     }
#
#     # 发送PUT请求以更新文件
#     put_url = f'https://gitee.com/api/v5/repos/{username}/{repo_name}/contents{path}{file_name}'
#     response = requests.put(put_url, headers=headers, json=data)
#
#     # 打印响应结果
#     print(response.json())


if __name__ == '__main__':
    removeIfExist(username, repo_name, path, access_token, file_name)
    uploadNewFileToGitee(username, repo_name, path, access_token, file_name)
    # updateFileToGitee(username, repo_name, path, access_token, file_name)
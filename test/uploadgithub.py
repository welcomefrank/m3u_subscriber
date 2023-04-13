import requests
import base64
import easywebdav


def getCorrectUrl(bakenStr):
    url_parts = bakenStr.split('/')
    cleaned_parts = [part for part in url_parts if part != '']
    cleaned_url = '/'.join(cleaned_parts)
    return cleaned_url


# Function to remove a file if it exists in the Github repository
def removeIfExist(username, repo_name, path, access_token, file_name):
    bakenStr = f'{username}/{repo_name}/contents/{path}/{file_name}'
    url = f'https://api.github.com/repos/{getCorrectUrl(bakenStr)}'
    headers = {'Authorization': f'token {access_token}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        file_details = response.json()
        sha = file_details['sha']
        commit_message = 'Delete existing file'
        data = {
            "message": commit_message,
            "sha": sha,
        }
        response = requests.delete(url, headers=headers, json=data)
        if response.status_code == 200:
            print(f'Successfully deleted file {file_name} in Github repository.')
        else:
            print(f'Error deleting file {file_name} from Github repository.')


# Function to upload a new file to the Github repository
def uploadNewFileToGithub(username, repo_name, path, access_token, file_name):
    bakenStr = f'{username}/{repo_name}/contents/{path}/{file_name}'
    url = f'https://api.github.com/repos/{getCorrectUrl(bakenStr)}'
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': f'token {access_token}',
    }
    with open('/' + file_name, 'rb') as f:
        file_content = f.read()
    b64_file_content = base64.b64encode(file_content).decode('utf-8')
    commit_message = 'Upload a file'
    data = {
        'message': commit_message,
        'content': b64_file_content,
    }
    response = requests.put(url, headers=headers, json=data)
    if response.status_code == 201:
        print(f'Successfully uploaded file {file_name} to Github repository.')
    else:
        print(f'Error uploading file {file_name} to Github repository.')


# Function to update file in the Github repository
def updateFileToGithub(file_name):
    # Github repository details
    global github_username
    global github_reponame
    global github_path
    global github_access_token

    # Initialize variables from Redis or config file
    username = '11'
    repo_name = '111'
    path = '/'
    access_token = '111111'

    try:
        removeIfExist(username, repo_name, path, access_token, file_name)
    except:
        pass
    try:
        uploadNewFileToGithub(username, repo_name, path, access_token, file_name)
    except:
        pass


####################gitee
# 检查文件是否已经存在于gitee仓库，存在的话删除旧数据
def removeIfExist(username, repo_name, path, access_token, file_name):
    url = f'https://gitee.com/api/v5/repos/{username}/{repo_name}/contents{path}'
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
    # # 读取要上传的文件内容（bytes比特流）
    with open(f'/{file_name}', 'rb') as f:
        file_content = f.read()
    # 构建API请求URL和headers
    url = f'https://gitee.com/api/v5/repos/{username}/{repo_name}/contents{path}/{file_name}'
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


##################################webdav########################################################


# Function to remove a file if it exists in the WebDAV repository
def removeIfExistWebDav(server_url, username, password, base_path, file_name, port):
    url = f"{server_url}:{port}/{base_path}/{file_name}"
    url = f'http://{getCorrectUrl(url)}'
    response = requests.head(url, auth=(username, password))
    if response.status_code == 200:
        response = requests.delete(url, auth=(username, password))
        if response.status_code == 204:
            print(f"Successfully deleted file {file_name} in WebDAV repository.")
    else:
        print(f"File {file_name} does not exist in WebDAV repository, skipping deletion.")


# Function to upload a new file to the WebDAV repository
def uploadNewFileToWebDAV(server_url, username, password, base_path, file_name, port):
    url = f"{server_url}:{port}/{base_path}/{file_name}"
    url = f'http://{getCorrectUrl(url)}'
    with open('/' + file_name, "rb") as f:
        file_content = f.read()
    response = requests.put(url, auth=(username, password), data=file_content)
    if response.status_code == 201:
        print(f"Successfully uploaded file {file_name} to WebDAV repository.")


# Function to update file in the WebDAV repository
def updateFileToWebDAV(file_name):
    # Initialize variables from Redis or config file
    server_url = '192.168.5.1'
    port = '5244'
    username = 'pi'
    password = '1111111'
    base_path = '/dav/local/'

    try:
        removeIfExistWebDav(server_url, username, password, base_path, file_name, port)
    except Exception as e:
        print(e)
        pass
    try:
        uploadNewFileToWebDAV(server_url, username, password, base_path, file_name, port)
    except Exception as e:
        print(e)
        pass


if __name__ == '__main__':
    updateFileToGithub("BDnsmasq.conf")
    #updateFileToWebDAV("openclash-fallback-filter-domain.conf")

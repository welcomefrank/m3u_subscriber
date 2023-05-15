import urllib

import requests


# url-基础请求列表API地址(alist网站/alist/api/fs/list)
# path-迭代查询路径
# file_url_dict 已经捕获到的文件(只存储视频文件)
# 新的路径
def getPathBase(url, path, file_url_dict, future_path_dict):
    if path:
        if not path.startswith('/'):
            path = '/' + path
        if path.endswith('/'):
            path = path[:-1]
        url = f'{url}?path={path}'
    try:
        response = requests.get(url)
        json_data = response.json()
        content = json_data['data']['content']
        for item in content:
            #source = {}
            # 名字
            name = item['name']
            # 文件大小
            # size = item['size']
            # 修改时间
            # modified = item['modified']
            # false-不是文件夹 true-是文件夹
            is_dir = item['is_dir']
            # 是文件夹，计算下一级目录，等待再次访问
            if is_dir:
                # source['is_dir'] = is_dir
                # source['name'] = path + '/' + name
                if path:
                    future_path_dict[f'{path}/{name}'] = ''
                else:
                    future_path_dict[f'/{name}'] = ''
                # result_list.append(f'{path}/{name}')
            # 是文件，直接存储
            else:
                if name.lower().endswith(
                        (".mp4", ".mkv", ".avi", '.ts', '.mov', '.fly', '.mpg', '.wmv', '.m4v',
                         '.mpeg', '.3gp', '.rmvb', '.rm')):
                    if path:
                        future_path = f'https://imexcloud.top/alist/d{path}/{name}'
                    else:
                        future_path = f'https://imexcloud.top/alist/d/{name}'
                    encoded_url = urllib.parse.quote(future_path, safe=':/')
                    file_url_dict[encoded_url] = ''
    except Exception as e:
        pass
    # return result_list


baseurl = 'https://imexcloud.top'
if not baseurl.endswith('/'):
    baseurl += '/'
api_part = 'alist/api/fs/list'

full_url = baseurl + api_part

# 找到的文件链接
file_dict = {}
# 需要迭代访问的路径
future_path_dict = {}
getPathBase(full_url, None, file_dict, future_path_dict)
while len(future_path_dict) > 0:
    tmp_future_path_dict = {}
    for pathbase in future_path_dict.keys():
        getPathBase(full_url, pathbase, file_dict, tmp_future_path_dict)
    future_path_dict.clear()
    future_path_dict.update(tmp_future_path_dict)

for key in file_dict.keys():
    print(key)



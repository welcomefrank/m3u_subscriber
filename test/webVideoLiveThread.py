import asyncio
import os

import aiofiles
import aiohttp
import urllib


# url-基础请求列表API地址(alist网站/alist/api/fs/list)
# path-迭代查询路径
# file_url_dict 已经捕获到的文件(只存储视频文件)
# 新的路径
async def getPathBase(site, url, path, file_url_dict, future_path_set, sem, session):
    if path:
        if not path.startswith('/'):
            path = '/' + path
        if path.endswith('/'):
            path = path[:-1]
        url = f'{url}?path={path}'
    try:
        async with sem, session.get(url) as response:
            json_data = await response.json()
            content = json_data['data']['content']
            for item in content:
                # 名字
                name = item['name']
                # false-不是文件夹 true-是文件夹
                is_dir = item['is_dir']
                # 是文件夹，计算下一级目录，等待再次访问
                if is_dir:
                    if path:
                        future_path_set.add(f'{path}/{name}')
                    else:
                        future_path_set.add(f'/{name}')
                # 是文件，直接存储
                else:
                    if name.lower().endswith(
                            (".mp4", ".mkv", ".avi", '.ts', '.mov', '.fly', '.mpg', '.wmv', '.m4v',
                             '.mpeg', '.3gp', '.rmvb', '.rm')):
                        if path:
                            future_path = f'{site}d{path}/{name}'
                            str = path.split('/')[-1]
                            groupName = f'Alist-{str}'
                        else:
                            future_path = f'{site}d/{name}'
                            groupName = 'Alist-无分组'
                        encoded_url = urllib.parse.quote(future_path, safe=':/')
                        link = f'#EXTINF:-1 group-title="{groupName}"  tvg-name="{name}",{name}\n'
                        file_url_dict[encoded_url] = link
                        pathxxx = f"{secret_path}webdavPublic.m3u"
                        async with aiofiles.open(pathxxx, 'a', encoding='utf-8') as f:  # 异步的方式写入内容
                            await f.write(f'{link}{encoded_url}\n')
    except Exception as e:
        pass


secret_path = '/app/secret/'


async def main(alist_url_dict):
    path = f"{secret_path}webdavPublic.m3u"
    if os.path.exists(path):
        os.remove(path)
    # baseurl = 'https://imexcloud.top/alist'
    # baseurl = 'https://pan.clun.top/'
    # baseurl = 'https://pan.ecve.cn'
    # if not baseurl.endswith('/'):
    #     baseurl += '/'
    api_part = 'api/fs/list'

    # full_url = baseurl + api_part

    # 找到的文件链接
    file_dict = {}
    # 需要迭代访问的路径
    future_path_set = set()

    sem = asyncio.Semaphore(1000)  # 限制TCP连接的数量为100个
    async with aiohttp.ClientSession() as session:
        for site in alist_url_dict.keys():

            if not site.endswith('/'):
                site += '/'
            # api_part = 'api/fs/list'

            full_url = site + api_part
            await getPathBase(site, full_url, None, file_dict, future_path_set, sem, session)

            async def process_path(pathbase):
                await getPathBase(site, full_url, pathbase, file_dict, future_path_set, sem, session)

            while len(future_path_set) > 0:
                tasks = [process_path(pathbase) for pathbase in future_path_set]
                future_path_set.clear()
                await asyncio.gather(*tasks)

    for key in file_dict.keys():
        print(key)


if __name__ == "__main__":
    # alist_url_dict = {'https://pan.ecve.cn': '', 'https://imexcloud.top/alist': '', 'https://pan.clun.top/': ''}
    alist_url_dict = {'https://pan.ecve.cn/': ''}
    asyncio.run(main(alist_url_dict))

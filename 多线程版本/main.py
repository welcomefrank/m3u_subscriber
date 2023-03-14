import concurrent
import json
import math
import os
import queue
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import redis
from flask import Flask, jsonify, request, send_file, render_template

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

r = redis.Redis(host='localhost', port=6379)


@app.route('/')
def index():
    return render_template('index.html')


# redis增加和修改
def redis_add(key, value):
    r.set(key, value)


# redis查询
def redis_get(key):
    return r.get(key)


# redis删除
def redis_del(key):
    if r.exists(key):
        r.delete(key)


# redis存储map字典，字典主键唯一，重复主键只会复写
def redis_add_map(key, my_dict):
    r.hmset(key, my_dict)


# redis取出map字典
def redis_get_map(key):
    redis_dict = r.hgetall(key)
    python_dict = {key.decode('utf-8'): value.decode('utf-8') for key, value in redis_dict.items()}
    return python_dict


# redis取出map字典key
def redis_get_map_keys(key):
    redis_dict = r.hgetall(key)
    array = [key for key in redis_dict.keys()]
    return array


# redis删除map字典
def redis_del_map(key):
    r.delete(key)


# 删除全部本地直播源
@app.route('/removeallm3u', methods=['GET'])
def removeallm3u():
    redis_del_map("localm3u")
    return "success"


# 删除全部直播源订阅链接
@app.route('/removem3ulinks', methods=['GET'])
def removem3ulinks():
    redis_del_map("m3ulink")
    return "success"


# 导出本地永久直播源
@app.route('/download_m3u_file', methods=['GET'])
def download_m3u_file():
    my_dict = redis_get_map("localm3u")
    distribute_data(my_dict, "/app/temp_m3u.m3u", 100)
    # 发送JSON文件到前端
    return send_file("temp_m3u.m3u", as_attachment=True)


# 手动上传m3u文件把直播源保存到数据库
@app.route('/upload_m3u_file', methods=['POST'])
def upload_m3u_file():
    file = request.files['file']
    # file_content = file.read().decode('utf-8')
    file_content = file.read()
    # file_content = read_file_with_encoding(file)
    my_dict = formatdata_multithread(file_content.splitlines(), 100)
    # my_dict = formattxt_multithread(file_content.splitlines(), 100)
    redis_add_map("localm3u", my_dict)
    return '文件已上传'


# 删除直播源
@app.route('/deletem3udata', methods=['POST'])
def deletem3udata():
    # 获取 HTML 页面发送的 POST 请求参数
    deleteurl = request.json.get('deletem3u')
    r.hdel('localm3u', deleteurl)
    return jsonify({'deletem3udata': "delete success"})


# 添加直播源
@app.route('/addm3udata', methods=['POST'])
def addm3udata():
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addm3u')
    name = request.json.get('name')
    my_dict = {addurl: name}
    redis_add_map("localm3u", my_dict)
    return jsonify({'addresult': "add success"})


# 拉取全部本地直播源
@app.route('/getm3udata', methods=['GET'])
def getm3udata():
    return jsonify(redis_get_map("localm3u"))


# 添加直播源到本地
@app.route('/savem3uarea', methods=['POST'])
def savem3uarea():
    # 获取 HTML 页面发送的 POST 请求参数
    m3utext = request.json.get('m3utext')
    # 格式优化
    my_dict = formattxt_multithread(m3utext.split("\n"), 10)
    redis_add_map("localm3u", my_dict)
    return jsonify({'addresult': "add success"})


# 定时器每隔半小时自动刷新订阅列表
def timer_func():
    while True:
        chaoronghe()
        reloadwhitelist()
        time.sleep(3600)  # 等待1小时


# 添加直播源订阅
@app.route('/addnewm3u', methods=['POST'])
def addnewm3u():
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    my_dict = {addurl: name}
    redis_add_map("m3ulink", my_dict)
    return jsonify({'addresult': "add success"})


# 删除直播源订阅
@app.route('/deletewm3u', methods=['POST'])
def deletewm3u():
    # 获取 HTML 页面发送的 POST 请求参数
    deleteurl = request.json.get('deleteurl')
    r.hdel('m3ulink', deleteurl)
    return jsonify({'deleteresult': "delete success"})


# 拉取全部直播源订阅
@app.route('/getall', methods=['GET'])
def getall():
    return jsonify(redis_get_map("m3ulink"))


def fetch_url(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        m3u_string = response.text
        m3u_string += "\n"
        return m3u_string
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch URL: {url}")
        print(e)
        return ""


def write_to_file(data, file):
    with open(file, 'a', encoding='utf-8') as f:
        for k, v in data:
            f.write(f'{v}{k}\n')


def worker(queue, file):
    while True:
        data = queue.get()
        if data is None:
            break
        write_to_file(data, file)
        queue.task_done()


# len(urls)
def download_files(urls):
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(urls)) as executor:
            results = list(executor.map(fetch_url, urls))
        # 等待所有任务执行完毕
        executor.shutdown(wait=True)
        # return results
        return "".join(results)
    except:
        return ""


# 全部订阅链接超融合
@app.route('/chaoronghe', methods=['GET'])
def chaoronghe():
    results = redis_get_map_keys("m3ulink")
    result = download_files(results)
    # 格式优化
    # my_dict = formattxt_multithread(result.split("\n"), 100)
    my_dict = formattxt_multithread(result.splitlines(), 100)
    if len(my_dict) == 0:
        return "empty"
    old_dict = redis_get_map("localm3u")
    my_dict.update(old_dict)
    # 同步方法写出全部配置
    distribute_data(my_dict, "/A.m3u", 100)
    redis_add_map("localm3u", my_dict)
    # 异步缓慢检测出有效链接
    # asyncio.run(asynctask(my_dict))
    return "result"


# 国外dns屏蔽中国域名，填写中国域名白名单订阅
def reloadwhitelist():
    links = [
        "https://raw.githubusercontent.com/hezhijie0327/GFWList2AGH/main/gfwlist2domain/whitelist_full.txt",
        "https://raw.githubusercontent.com/pluwen/china-domain-allowlist/main/allow-list.sorl",
        "https://raw.githubusercontent.com/mawenjian/china-cdn-domain-whitelist/master/china-cdn-domain-whitelist.txt",
        "https://raw.githubusercontent.com/mawenjian/china-cdn-domain-whitelist/master/china-top-website-whitelist.txt",

    ]


# 国内dns屏蔽外国域名，填写中国域名黑名单/外国域名白名单订阅
def reloadwhitelist():
    links = [
        "https://raw.githubusercontent.com/hezhijie0327/GFWList2AGH/main/gfwlist2domain/blacklist_full.txt",
        ""
    ]


# async def asynctask(dict):
#     async with aiohttp.ClientSession() as session:
#         for url, value in dict.items():
#             try:
#                 async with session.get(url) as resp:
#                     if resp.status == 200:
#                         # 如果url有效，将它和值写入m3u文件
#                         with open('/B.m3u', 'a') as f:
#                             f.write(f'{value},{url}\n')
#             except:
#                 pass


# def check_url(url):
#     try:
#         resp = requests.get(url, timeout=5)
#         if resp.status_code == 200:
#             return True
#         else:
#             return False
#     except:
#         return False

# 多线程写入A.m3u
def distribute_data(data, file, num_threads):
    if len(data.items()) == 0:
        return
    if os.path.exists(file):
        os.remove(file)
    # 将字典转换为元组列表，并按照键的顺序排序
    items = sorted(data.items())
    # 计算每个线程处理的数据大小
    chunk_size = (len(items) + num_threads - 1) // num_threads

    # 将数据切分为若干个块，每个块包含 chunk_size 个键值对
    chunks = [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]

    # 创建一个任务队列，并向队列中添加任务
    task_queue = queue.Queue()
    for chunk in chunks:
        task_queue.put(chunk)

    # 创建线程池
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(task_queue, file))
        t.start()
        threads.append(t)

    # 等待任务队列中的所有任务完成
    task_queue.join()

    # 向任务队列中添加 num_threads 个 None 值，以通知线程退出
    for i in range(num_threads):
        task_queue.put(None)

    # 等待所有线程退出
    for t in threads:
        t.join()


# def check_live_streams(mapdata):
#     cpu_count = multiprocessing.cpu_count()
#     with ThreadPoolExecutor(max_workers=cpu_count) as executor:
#         futures = [executor.submit(check_url, url) for url in mapdata.keys()]
#     return {url: mapdata[url] for url, future in zip(mapdata.keys(), futures) if future.result()}


def formattxt_multithread(data, num_threads):
    my_dict = {}
    # 计算每个线程处理的数据段大小
    step = math.ceil(len(data) / num_threads)
    # 创建线程池对象
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        # 提交任务到线程池中
        for i in range(num_threads):
            start_index = i * step
            executor.submit(process_data, data, start_index, step, my_dict)
    # 等待所有任务执行完毕
    executor.shutdown(wait=True)
    return my_dict


# 上传文件bytes格式规整
def format_data(data, index, step, my_dict):
    defalutname = "佚名"
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        # print(type(data[i]))
        line = data[i].decode("utf-8").strip()
        if not line:
            continue
        # 假定直播名字和直播源不在同一行
        if line.startswith("#EXTINF"):
            continue
        # 不是http开头，可能是直播源
        if not line.startswith(("http", "rtsp", "rtmp", "P2p")):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,(http|rtsp|rtmp|P2p)", line):
                name, url = line.split(",", 1)
                searchurl = url
                if searchurl in my_dict.keys():
                    continue
                if name:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{name}"\n'
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
            elif re.match(r"^[^#].*，(http|rtsp|rtmp|P2p)", line):
                name, url = line.split("，", 1)
                searchurl = url
                if searchurl in my_dict.keys():
                    continue
                if name:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{name}"\n'
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
        # http开始
        else:
            # 去重复
            searchurl = line
            if searchurl in my_dict.keys():
                continue
            # 第一行的无名直播
            if i == 0 and index == 0:
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                continue
            preline = data[i - 1].decode("utf-8").strip()
            # 没有名字
            if not preline:
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                continue
            # 不是名字
            if not preline.startswith("#EXTINF"):
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                continue
            # 有名字
            else:
                my_dict[searchurl] = f'{preline}\n'
                continue


# 字符串内容处理
def process_data(data, index, step, my_dict):
    defalutname = "佚名"
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        # print(type(data[i]))
        line = data[i].strip()
        if not line:
            continue
        # 假定直播名字和直播源不在同一行
        if line.encode().startswith(b"#EXTINF"):
            continue
        # 不是http开头，可能是直播源
        if not line.encode().startswith((b"http", b"rtsp", b"rtmp", b"P2p")):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,(http|rtsp|rtmp|P2p)", line):
                name, url = line.split(",", 1)
                searchurl = url
                if searchurl in my_dict.keys():
                    continue
                if name:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{name}"\n'
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
            elif re.match(r"^[^#].*，(http|rtsp|rtmp|P2p)", line):
                name, url = line.split("，", 1)
                searchurl = url
                if searchurl in my_dict.keys():
                    continue
                if name:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{name}"\n'
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
        # http开始
        else:
            searchurl = line
            if searchurl in my_dict.keys():
                continue
            # 第一行的无名直播
            if i == 0 and index == 0:
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                continue
            preline = data[i - 1].strip()
            # 没有名字
            if not preline:
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                continue
            # 不是名字
            if not preline.encode().startswith(b"#EXTINF"):
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                continue
            # 有裸名字或者#EXTINF开始但是没有tvg-name\tvg-id\group-title
            else:
                # if not any(substring in line for substring in ["tvg-name", "tvg-id", "group-title"]):
                my_dict[searchurl] = f'{preline}\n'
                continue


def generate_json_string(mapname):
    m3ulink = redis_get_map(mapname)
    # 将字典转换为JSON字符串并返回
    json_str = json.dumps(m3ulink)
    return json_str


# 导出直播源订阅配置
@app.route('/download_json_file', methods=['GET'])
def download_json_file():
    # 生成JSON文件数据
    json_data = generate_json_string("m3ulink")
    if os.path.exists("/app/temp_json.json"):
        os.remove("/app/temp_json.json")
    # 保存JSON数据到临时文件
    with open("/app/temp_json.json", 'w') as f:
        f.write(json_data)
    # 发送JSON文件到前端
    return send_file("temp_json.json", as_attachment=True)


# 上传直播源订阅配置集合文件
@app.route('/upload_json_file', methods=['POST'])
def upload_json_file():
    try:
        # 获取POST请求中的JSON文件内容
        file_content = request.get_data()
        # 将字节对象解码为字符串
        file_content_str = file_content.decode('utf-8')
        # 将JSON字符串保存到临时文件
        with open('/tmp_data.json', 'w') as f:
            json.dump(json.loads(file_content_str), f)
        with open("/tmp_data.json", 'r') as f:
            json_dict = json.load(f)
        redis_add_map("m3ulink", json_dict)
        os.remove("/tmp_data.json")
        return jsonify({'success': True})
    except Exception as e:
        print("An error occurred: ", e)
        return jsonify({'success': False})


def formatdata_multithread(data, num_threads):
    my_dict = {}
    # 计算每个线程处理的数据段大小
    step = math.ceil(len(data) / num_threads)
    # 创建线程池对象
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        # 提交任务到线程池中
        for i in range(num_threads):
            start_index = i * step
            executor.submit(format_data, data, start_index, step, my_dict)
    # 等待所有任务执行完毕
    executor.shutdown(wait=True)
    return my_dict


# 手动上传m3u文件格式化统一转换
@app.route('/process-file', methods=['POST'])
def process_file():
    file = request.files['file']
    # file_content = file.read().decode('utf-8')
    file_content = file.read()
    # file_content = read_file_with_encoding(file)
    my_dict = formatdata_multithread(file_content.splitlines(), 100)
    # my_dict = formattxt_multithread(file_content.splitlines(), 100)
    # my_dict = formatdata_multithread(file.readlines(), 100)
    distribute_data(my_dict, "/app/tmp.m3u", 100)
    return send_file("tmp.m3u", as_attachment=True)


# init_db()

if __name__ == '__main__':
    timer_thread = threading.Thread(target=timer_func)
    timer_thread.start()
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    finally:
        timer_thread.join()

import abc
import asyncio
import concurrent
import ipaddress
import json
import math
import os
import queue
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import redis
import requests
from flask import Flask, jsonify, request, send_file, render_template

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

r = redis.Redis(host='localhost', port=6379)

##########################################################redis key#############################################
REDIS_KEY_M3U_LINK = "m3ulink"
REDIS_KEY_M3U_DATA = "localm3u"
# 白名单下载链接
REDIS_KEY_WHITELIST_LINK = "whitelistlink"
# 白名单adguardhome
REDIS_KEY_WHITELIST_DATA = "whitelistdata"
# 白名单dnsmasq
REDIS_KEY_WHITELIST_DATA_DNSMASQ = "whitelistdatadnsmasq"
# 白名单whitedomain
REDIS_KEY_DOMAIN_DATA = "whitedomain"
# 黑名单下载链接
REDIS_KEY_BLACKLIST_LINK = "blacklistlink"
# 黑名单adguardhome
REDIS_KEY_BLACKLIST_DATA = "blacklistdata"
# 黑名单openclash-fallback-filter-domain
REDIS_KEY_BLACKLIST_OPENCLASH_FALLBACK_FILTER_DOMAIN_DATA = "blacklistopfallbackfilterdomaindata"
# 黑名单blackdomain
REDIS_KEY_BLACKLIST_DOMAIN_DATA = "blackdomain"
# 白名单中国大陆IPV4下载链接
REDIS_KEY_WHITELIST_IPV4_LINK = "whitelistipv4link"
# 白名单中国大陆IPV4下载数据
REDIS_KEY_WHITELIST_IPV4_DATA = "whitelistipv4data"
# 白名单中国大陆IPV6下载链接
REDIS_KEY_WHITELIST_IPV6_LINK = "whitelistipv6link"
# 白名单中国大陆IPV6下载数据
REDIS_KEY_WHITELIST_IPV6_DATA = "whitelistipv6data"
# 密码本下载链接
REDIS_KEY_PASSWORD_LINK = "passwordlink"
allListArr = [REDIS_KEY_M3U_LINK, REDIS_KEY_WHITELIST_LINK, REDIS_KEY_BLACKLIST_LINK, REDIS_KEY_WHITELIST_IPV4_LINK,
              REDIS_KEY_WHITELIST_IPV6_LINK, REDIS_KEY_PASSWORD_LINK]

# Adguardhome屏蔽前缀
BLACKLIST_ADGUARDHOME_FORMATION = "240.0.0.0 "
# dnsmasq白名单前缀
BLACKLIST_DNSMASQ_FORMATION_LEFT = "server=/"
# dnsmasq白名单后缀
BLACKLIST_DNSMASQ_FORMATION_right = "/114.114.114.114"
# 用于匹配纯粹域名的正则表达式
domain_regex = r'^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$'
# 用于匹配泛化匹配的域名规则的正则表达式
wildcard_regex = r'^\*\.[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$'
# 用于匹配泛化匹配的域名规则的正则表达式
wildcard_regex2 = r'^\+\.[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$'
# 用于匹配dnsmasq白名单格式
pattern = r'^server=\/[a-zA-Z0-9.-]+\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9.-]+)$'
OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT = "    - \""
OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT = "\""


@app.route('/')
def index():
    return render_template('index.html')


##########################################################redis数据库操作#############################################
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


#########################################################通用工具区#################################################
# 上传订阅配置
def upload_json(request, rediskey, filename):
    try:
        # 获取POST请求中的JSON文件内容
        file_content = request.get_data()
        # 将字节对象解码为字符串
        file_content_str = file_content.decode('utf-8')
        # 将JSON字符串保存到临时文件
        with open(filename, 'w') as f:
            json.dump(json.loads(file_content_str), f)
        with open(filename, 'r') as f:
            json_dict = json.load(f)
        redis_add_map(rediskey, json_dict)
        os.remove(filename)
        return jsonify({'success': True})
    except Exception as e:
        print("An error occurred: ", e)
        return jsonify({'success': False})


# 定时器每隔半小时自动刷新订阅列表
def timer_func():
    while True:
        chaoronghe()
        chaoronghe2()
        chaoronghe3()
        chaoronghe4()
        chaoronghe5()
        time.sleep(43200)  # 等待12小时


def check_file(m3u_dict):
    try:
        """
            检查A.m3u文件是否存在且没有被占用
            """
        if len(m3u_dict) == 0:
            return
        if os.path.exists("/alive.m3u"):
            os.remove("/alive.m3u")
            # 异步缓慢检测出有效链接
        asyncio.run(asynctask(m3u_dict))
    except:
        pass


def check_url(url):
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return True
        else:
            return False
    except:
        return False


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


# 添加一条数据进入字典
def addlist(request, rediskey):
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    my_dict = {addurl: name}
    redis_add_map(rediskey, my_dict)
    return jsonify({'addresult': "add success"})


async def asynctask(dict):
    async with aiohttp.ClientSession() as session:
        for url, value in dict.items():
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        # 如果url有效，将它和值写入m3u文件
                        with open('/alive.m3u', 'a') as f:
                            f.write(f'{value}{url}\n')
            except:
                pass


def chaorongheBase(redisKeyLink, processDataMethodName, redisKeyData, fileName):
    results = redis_get_map_keys(redisKeyLink)
    result = download_files(results)
    # 格式优化
    # my_dict = formattxt_multithread(result.split("\n"), 100)
    my_dict = formattxt_multithread(result.splitlines(), 100, processDataMethodName)
    # my_dict = formattxt_multithread(result.splitlines(), 100)
    if len(my_dict) == 0:
        return "empty"
    old_dict = redis_get_map(redisKeyData)
    my_dict.update(old_dict)
    # 同步方法写出全部配置
    distribute_data(my_dict, fileName, 100)
    redis_add_map(redisKeyData, my_dict)
    # 异步缓慢检测出有效链接
    # asyncio.run(asynctask(my_dict))
    if fileName == "/A.m3u":
        thread = threading.Thread(target=check_file, args=(my_dict,))
        thread.start()
    return "result"


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
        if not line.startswith(("http", "rtsp", "rtmp")):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,(http|rtsp|rtmp)", line):
                name, url = line.split(",", 1)
                searchurl = url
                if searchurl in my_dict.keys():
                    continue
                if name:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{name}"\n'
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
            elif re.match(r"^[^#].*，(http|rtsp|rtmp)", line):
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


# 抽象类，定义抽象方法process_data_abstract
class MyAbstractClass(abc.ABC):
    @abc.abstractmethod
    def process_data_abstract(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract2(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract3(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract4(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract5(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract6(self, data, index, step, my_dict):
        pass

    @abc.abstractmethod
    def process_data_abstract7(self, data, index, step, my_dict):
        pass


# 处理数据的实现类
class MyConcreteClass(MyAbstractClass):
    # 实现抽象方法
    # 处理M3U数据的实现类
    def process_data_abstract(self, data, index, step, my_dict):
        process_data(data, index, step, my_dict)
        # 实现代码
        pass

    # 处理域名名单转换Adguardhome的实现类
    def process_data_abstract2(self, data, index, step, my_dict):
        process_data_domain(data, index, step, my_dict)
        # 实现代码
        pass

    # 处理域名名单转换dnsmasq的实现类
    def process_data_abstract3(self, data, index, step, my_dict):
        process_data_domain_dnsmasq(data, index, step, my_dict)
        # 实现代码
        pass

    # 处理域名合并的实现类
    def process_data_abstract4(self, data, index, step, my_dict):
        process_data_domain_collect(data, index, step, my_dict)
        # 实现代码
        pass

    # 处理合并ipv4的实现类
    def process_data_abstract5(self, data, index, step, my_dict):
        process_data_ipv4_collect(data, index, step, my_dict)
        # 实现代码
        pass

    # 处理合并ipv6的实现类
    def process_data_abstract6(self, data, index, step, my_dict):
        process_data_ipv6_collect(data, index, step, my_dict)
        # 实现代码
        pass

    # 黑名单转换成openclash-fallbackfilter-domain
    def process_data_abstract7(self, data, index, step, my_dict):
        process_data_domain_openclash_fallbackfilter(data, index, step, my_dict)
        # 实现代码
        pass


def formattxt_multithread(data, num_threads, method_name):
    my_dict = {}
    # 计算每个线程处理的数据段大小
    step = math.ceil(len(data) / num_threads)
    # 创建线程池对象
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        # 提交任务到线程池中
        for i in range(num_threads):
            start_index = i * step
            executor.submit(getattr(MyConcreteClass(), method_name), data, start_index, step, my_dict)
    # 等待所有任务执行完毕
    executor.shutdown(wait=True)
    return my_dict


# 字符串内容处理-域名转openclash-fallbackfilter-domain
def process_data_domain_openclash_fallbackfilter(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # 判断是不是+.域名
        if re.match(wildcard_regex2, line):
            my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
        # 判断是不是域名
        elif re.match(domain_regex, line):
            my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            if not line.encode().startswith(b"www"):
                my_dict[
                    OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "+." + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
        # 判断是不是*.域名
        elif re.match(wildcard_regex, line):
            my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line[2:] + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            my_dict[
                OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "+." + line[2:] + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
        elif line.encode().startswith(b"."):
            my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "+" + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""


# 字符串内容处理-域名转adguardhome屏蔽
def process_data_domain(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # 判断是不是域名或者*.域名
        if re.match(domain_regex, line) or re.match(wildcard_regex, line):
            my_dict["||" + line + "^"] = ""
            if not line.encode().startswith((b"www", b".", b"*")):
                my_dict["||" + "*." + line + "^"] = ""
            if line.encode().startswith(b"."):
                my_dict["||" + "*" + line + "^"] = ""


def is_ipv4_network(ipv4_str):
    try:
        network = ipaddress.IPv4Network(ipv4_str)
        return True
    except ValueError:
        return False


def is_ipv6_network(ipv6_str):
    try:
        network = ipaddress.IPv6Network(ipv6_str)
        return True
    except ValueError:
        return False


# 字符串内容处理-ipv4合并
def process_data_ipv4_collect(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # 判断是不是域名或者*.域名
        if is_ipv4_network(line):
            my_dict[line] = ""


# 字符串内容处理-ipv6合并
def process_data_ipv6_collect(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # 判断是不是域名或者*.域名
        if is_ipv6_network(line):
            my_dict[line] = ""


# 字符串内容处理-域名合并
def process_data_domain_collect(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # 判断是不是域名或者*.域名
        if re.match(domain_regex, line) or re.match(wildcard_regex, line):
            my_dict[line] = ""


# 字符串内容处理-域名转dnsmasq白名单
def process_data_domain_dnsmasq(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # 判断是不是域名或者*.域名
        if re.match(domain_regex, line) or re.match(wildcard_regex, line):
            my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""
            if not line.encode().startswith((b"www", b".", b"*")):
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + "*." + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""
            if line.encode().startswith(b"."):
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + "*" + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""


# 字符串内容处理-m3u
def process_data(data, index, step, my_dict):
    defalutname = "佚名"
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        # print(type(data[i]))
        line = data[i].strip()
        # 空行
        if not line:
            continue
        # 假定直播名字和直播源不在同一行，跳过频道名字
        if line.encode().startswith(b"#EXTINF"):
            continue
        # 不是http开头，也可能是直播源
        if not line.encode().startswith((b"http", b"rtsp", b"rtmp")):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,(http|rtsp|rtmp)", line):
                name, url = line.split(",", 1)
                searchurl = url
                if searchurl in my_dict.keys():
                    continue
                if name:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{name}"\n'
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
            # 匹配格式：频道，url
            elif re.match(r"^[^#].*，(http|rtsp|rtmp)", line):
                name, url = line.split("，", 1)
                searchurl = url
                if searchurl in my_dict.keys():
                    continue
                if name:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{name}"\n'
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
        # http|rtsp|rtmp开始，跳过P2p
        elif not line.encode().startswith(b"P2p"):
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


# 一键导出全部json配置
def generate_multi_json_string(mapnameArr):
    finalDict = {}
    for name in mapnameArr:
        m3ulink = redis_get_map(name)
        finalDict[name] = m3ulink
    # 将字典转换为JSON字符串并返回
    json_str = json.dumps(finalDict)
    return json_str


# 上传订阅配置
def upload_oneKey_json(request, filename):
    try:
        # 获取POST请求中的JSON文件内容
        file_content = request.get_data()
        # 将字节对象解码为字符串
        file_content_str = file_content.decode('utf-8')
        # 将JSON字符串保存到临时文件
        with open(filename, 'w') as f:
            json.dump(json.loads(file_content_str), f)
        with open(filename, 'r') as f:
            json_dict = json.load(f)
        for cachekey, valuedict in json_dict.items():
            redis_add_map(cachekey, valuedict)
        os.remove(filename)
        return jsonify({'success': True})
    except Exception as e:
        print("An error occurred: ", e)
        return jsonify({'success': False})


def dellist(request, rediskey):
    # 获取 HTML 页面发送的 POST 请求参数
    deleteurl = request.json.get('deleteurl')
    r.hdel(rediskey, deleteurl)
    return jsonify({'deleteresult': "delete success"})


def download_json_file_base(redislinkKey, filename, outname):
    # 生成JSON文件数据
    json_data = generate_json_string(redislinkKey)
    if os.path.exists(filename):
        os.remove(filename)
    # 保存JSON数据到临时文件
    with open(filename, 'w') as f:
        f.write(json_data)
    # 发送JSON文件到前端
    return send_file(outname, as_attachment=True)


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

    # my_dict = methodA(formatMultiThreadName, [result.splitlines(), 100, processDataMethodName])
    # 定义方法A，接受一个函数名参数和一个参数列表
    # def methodA(methodName, params):
    #     # 使用eval()函数来执行传递进来的方法名对应的函数，并传递参数列表
    #     result = eval(methodName + '(' + ', '.join(str(p) for p in params) + ')')
    #     return result


############################################################协议区####################################################


# 一键上传全部配置集合文件
@app.route('/upload_json_file7', methods=['POST'])
def upload_json_file7():
    return upload_oneKey_json(request, "/tmp_data7.json")


# 一键导出全部配置
@app.route('/download_json_file7', methods=['GET'])
def download_json_file7():
    # 生成JSON文件数据
    json_data = generate_multi_json_string(allListArr)
    if os.path.exists("/app/allData.json"):
        os.remove("/app/allData.json")
    # 保存JSON数据到临时文件
    with open("/app/allData.json", 'w') as f:
        f.write(json_data)
    # 发送JSON文件到前端
    return send_file("allData.json", as_attachment=True)


# 删除密码
@app.route('/deletewm3u6', methods=['POST'])
def deletewm3u6():
    return dellist(request, REDIS_KEY_PASSWORD_LINK)


# 添加密码
@app.route('/addnewm3u6', methods=['POST'])
def addnewm3u6():
    return addlist(request, REDIS_KEY_PASSWORD_LINK)


# 导出密码配置
@app.route('/download_json_file6', methods=['GET'])
def download_json_file6():
    return download_json_file_base(REDIS_KEY_PASSWORD_LINK, "/app/temp_passwordlist.json",
                                   "temp_passwordlist.json")


# 拉取全部密码
@app.route('/getall6', methods=['GET'])
def getall6():
    return jsonify(redis_get_map(REDIS_KEY_PASSWORD_LINK))


# 删除全部密码
@app.route('/removem3ulinks6', methods=['GET'])
def removem3ulinks6():
    redis_del_map(REDIS_KEY_PASSWORD_LINK)
    return "success"


# 上传密码本配置集合文件
@app.route('/upload_json_file6', methods=['POST'])
def upload_json_file6():
    return upload_json(request, REDIS_KEY_PASSWORD_LINK, "/tmp_data6.json")


# 删除全部ipv6订阅链接
@app.route('/removem3ulinks5', methods=['GET'])
def removem3ulinks5():
    redis_del_map(REDIS_KEY_WHITELIST_IPV6_LINK)
    return "success"


# 全部ipv6订阅链接超融合
@app.route('/chaoronghe5', methods=['GET'])
def chaoronghe5():
    try:
        return chaorongheBase(REDIS_KEY_WHITELIST_IPV6_LINK, 'process_data_abstract6',
                              REDIS_KEY_WHITELIST_IPV6_DATA, "/ipv6.txt")
    except:
        pass


# 导出ipv6订阅配置
@app.route('/download_json_file5', methods=['GET'])
def download_json_file5():
    return download_json_file_base(REDIS_KEY_WHITELIST_IPV6_LINK, "/app/temp_ipv6listlink.json",
                                   "temp_ipv6listlink.json")


# 拉取全部ipv6订阅
@app.route('/getall5', methods=['GET'])
def getall5():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_IPV6_LINK))


# 删除ipv6订阅
@app.route('/deletewm3u5', methods=['POST'])
def deletewm3u5():
    return dellist(request, REDIS_KEY_WHITELIST_IPV6_LINK)


# 添加ipv6订阅
@app.route('/addnewm3u5', methods=['POST'])
def addnewm3u5():
    return addlist(request, REDIS_KEY_WHITELIST_IPV6_LINK)


# 上传中国ipv6订阅配置集合文件
@app.route('/upload_json_file5', methods=['POST'])
def upload_json_file5():
    return upload_json(request, REDIS_KEY_WHITELIST_IPV6_LINK, "/tmp_data5.json")


# 删除ipv4订阅
@app.route('/deletewm3u4', methods=['POST'])
def deletewm3u4():
    return dellist(request, REDIS_KEY_WHITELIST_IPV4_LINK)


# 添加ipv4订阅
@app.route('/addnewm3u4', methods=['POST'])
def addnewm3u4():
    return addlist(request, REDIS_KEY_WHITELIST_IPV4_LINK)


# 删除全部ipv4订阅链接
@app.route('/removem3ulinks4', methods=['GET'])
def removem3ulinks4():
    redis_del_map(REDIS_KEY_WHITELIST_IPV4_LINK)
    return "success"


# 全部ipv4订阅链接超融合
@app.route('/chaoronghe4', methods=['GET'])
def chaoronghe4():
    try:
        return chaorongheBase(REDIS_KEY_WHITELIST_IPV4_LINK, 'process_data_abstract5',
                              REDIS_KEY_WHITELIST_IPV4_DATA, "/ipv4.txt")
    except:
        pass


# 导出ipv4订阅配置
@app.route('/download_json_file4', methods=['GET'])
def download_json_file4():
    return download_json_file_base(REDIS_KEY_WHITELIST_IPV4_LINK, "/app/temp_ipv4listlink.json",
                                   "temp_ipv4listlink.json")


# 拉取全部ipv4订阅
@app.route('/getall4', methods=['GET'])
def getall4():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_IPV4_LINK))


# 上传中国ipv4订阅配置集合文件
@app.route('/upload_json_file4', methods=['POST'])
def upload_json_file4():
    return upload_json(request, REDIS_KEY_WHITELIST_IPV4_LINK, "/tmp_data4.json")


# 全部域名黑名单订阅链接超融合
@app.route('/chaoronghe3', methods=['GET'])
def chaoronghe3():
    try:
        return chaorongheBase(REDIS_KEY_BLACKLIST_LINK, 'process_data_abstract7',
                              REDIS_KEY_BLACKLIST_OPENCLASH_FALLBACK_FILTER_DOMAIN_DATA,
                              "/openclash-fallback-filter-domain.txt")
        # return chaorongheBase(REDIS_KEY_BLACKLIST_LINK, 'process_data_abstract2',
        #                       REDIS_KEY_BLACKLIST_DATA, "/C.txt")
    except:
        pass


# 删除全部白名单源订阅链接
@app.route('/removem3ulinks3', methods=['GET'])
def removem3ulinks3():
    redis_del_map(REDIS_KEY_BLACKLIST_LINK)
    return "success"


# 导出域名黑名单订阅配置
@app.route('/download_json_file3', methods=['GET'])
def download_json_file3():
    return download_json_file_base(REDIS_KEY_BLACKLIST_LINK, "/app/temp_blacklistlink.json", "temp_blacklistlink.json")


# 删除黑名单订阅
@app.route('/deletewm3u3', methods=['POST'])
def deletewm3u3():
    return dellist(request, REDIS_KEY_BLACKLIST_LINK)


# 添加黑名单订阅
@app.route('/addnewm3u3', methods=['POST'])
def addnewm3u3():
    return addlist(request, REDIS_KEY_BLACKLIST_LINK)


# 拉取全部黑名单订阅
@app.route('/getall3', methods=['GET'])
def getall3():
    return jsonify(redis_get_map(REDIS_KEY_BLACKLIST_LINK))


# 上传黑名单订阅配置集合文件
@app.route('/upload_json_file3', methods=['POST'])
def upload_json_file3():
    return upload_json(request, REDIS_KEY_BLACKLIST_LINK, "/tmp_data3.json")


# 删除全部白名单源订阅链接
@app.route('/removem3ulinks2', methods=['GET'])
def removem3ulinks2():
    redis_del_map(REDIS_KEY_WHITELIST_LINK)
    return "success"


# 导出域名白名单订阅配置
@app.route('/download_json_file2', methods=['GET'])
def download_json_file2():
    return download_json_file_base(REDIS_KEY_WHITELIST_LINK, "/app/temp_whitelistlink.json", "temp_whitelistlink.json")


# 全部域名白名单订阅链接超融合
@app.route('/chaoronghe2', methods=['GET'])
def chaoronghe2():
    try:
        # chaorongheBase(REDIS_KEY_WHITELIST_LINK, 'process_data_abstract4',
        #                REDIS_KEY_DOMAIN_DATA, "/WhiteDomain.txt")
        return chaorongheBase(REDIS_KEY_WHITELIST_LINK, 'process_data_abstract3',
                              REDIS_KEY_WHITELIST_DATA_DNSMASQ, "/BDnsmasq.txt")
        # return chaorongheBase(REDIS_KEY_WHITELIST_LINK, 'process_data_abstract2',
        #                       REDIS_KEY_WHITELIST_DATA, "/B.txt")
    except:
        pass


# 拉取全部白名单订阅
@app.route('/getall2', methods=['GET'])
def getall2():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_LINK))


# 添加白名单订阅
@app.route('/addnewm3u2', methods=['POST'])
def addnewm3u2():
    return addlist(request, REDIS_KEY_WHITELIST_LINK)


# 删除白名单订阅
@app.route('/deletewm3u2', methods=['POST'])
def deletewm3u2():
    return dellist(request, REDIS_KEY_WHITELIST_LINK)


# 上传白名单订阅配置集合文件
@app.route('/upload_json_file2', methods=['POST'])
def upload_json_file2():
    return upload_json(request, REDIS_KEY_WHITELIST_LINK, "/tmp_data2.json")


# 删除全部本地直播源
@app.route('/removeallm3u', methods=['GET'])
def removeallm3u():
    redis_del_map(REDIS_KEY_M3U_DATA)
    return "success"


# 删除全部直播源订阅链接
@app.route('/removem3ulinks', methods=['GET'])
def removem3ulinks():
    redis_del_map(REDIS_KEY_M3U_LINK)
    return "success"


# 导出本地永久直播源
@app.route('/download_m3u_file', methods=['GET'])
def download_m3u_file():
    my_dict = redis_get_map(REDIS_KEY_M3U_DATA)
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
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
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
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    return jsonify({'addresult': "add success"})


# 拉取全部本地直播源
@app.route('/getm3udata', methods=['GET'])
def getm3udata():
    return jsonify(redis_get_map(REDIS_KEY_M3U_DATA))


# 添加直播源到本地
@app.route('/savem3uarea', methods=['POST'])
def savem3uarea():
    # 获取 HTML 页面发送的 POST 请求参数
    m3utext = request.json.get('m3utext')
    # 格式优化
    my_dict = formattxt_multithread(m3utext.split("\n"), 10, 'process_data_abstract')
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    return jsonify({'addresult': "add success"})


# 添加直播源订阅
@app.route('/addnewm3u', methods=['POST'])
def addnewm3u():
    return addlist(request, REDIS_KEY_M3U_LINK)


# 删除直播源订阅
@app.route('/deletewm3u', methods=['POST'])
def deletewm3u():
    return dellist(request, REDIS_KEY_M3U_LINK)


# 拉取全部直播源订阅
@app.route('/getall', methods=['GET'])
def getall():
    return jsonify(redis_get_map(REDIS_KEY_M3U_LINK))


# 全部订阅链接超融合
@app.route('/chaoronghe', methods=['GET'])
def chaoronghe():
    try:
        return chaorongheBase(REDIS_KEY_M3U_LINK, 'process_data_abstract', REDIS_KEY_M3U_DATA,
                              "/A.m3u")
    except:
        pass


# 导出直播源订阅配置
@app.route('/download_json_file', methods=['GET'])
def download_json_file():
    return download_json_file_base(REDIS_KEY_M3U_LINK, "/app/temp_m3ulink.json", "temp_m3ulink.json")


# 上传直播源订阅配置集合文件
@app.route('/upload_json_file', methods=['POST'])
def upload_json_file():
    return upload_json(request, REDIS_KEY_M3U_LINK, "/tmp_data.json")


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

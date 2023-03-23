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
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import redis
import requests
# import base64
import time
from urllib.parse import urlparse, unquote
# import yaml
from flask import Flask, jsonify, request, send_file, render_template

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

r = redis.Redis(host='localhost', port=6379)

##########################################################redis key#############################################
REDIS_KEY_M3U_LINK = "m3ulink"
REDIS_KEY_M3U_DATA = "localm3u"
REDIS_KEY_M3U_EPG_LOGO = "m3uepglogo"
REDIS_KEY_M3U_EPG_GROUP = "m3uepggroup"
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
# 白名单adguardhome-m3u
REDIS_KEY_WHITELIST_M3U_DATA = "whitelistm3udata"
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
# 节点下载链接
REDIS_KEY_PROXIES_LINK = "proxieslink"
# 代理类型
REDIS_KEY_PROXIES_TYPE = "proxiestype"
# 代理转换配置模板(本地组+网络组):url,name
REDIS_KEY_PROXIES_MODEL = "proxiesmodel"
# 代理转换配置选择的模板:name
REDIS_KEY_PROXIES_MODEL_CHOSEN = "proxiesmodelchosen"
# 代理转换服务器订阅:url,name
REDIS_KEY_PROXIES_SERVER = "proxiesserver"
# 代理转换选择的服务器订阅:url,name
REDIS_KEY_PROXIES_SERVER_CHOSEN = "proxiesserverchosen"

allListArr = [REDIS_KEY_M3U_LINK, REDIS_KEY_WHITELIST_LINK, REDIS_KEY_BLACKLIST_LINK, REDIS_KEY_WHITELIST_IPV4_LINK,
              REDIS_KEY_WHITELIST_IPV6_LINK, REDIS_KEY_PASSWORD_LINK, REDIS_KEY_PROXIES_LINK, REDIS_KEY_PROXIES_TYPE,
              REDIS_KEY_PROXIES_MODEL, REDIS_KEY_PROXIES_MODEL_CHOSEN, REDIS_KEY_PROXIES_SERVER,
              REDIS_KEY_PROXIES_SERVER_CHOSEN]

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

# name,logo
CHANNEL_LOGO = {}
# name,group
CHANNEL_GROUP = {}
defalutname = "佚名"

# 订阅模板转换服务器地址API
URL = "http://192.168.5.1:25500/sub"
# m3u下载处理时提取直播源域名在adguardhome放行，只放行m3u域名不管分流
white_list_adguardhome = {}


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


def execute(method_name, sleepSecond):
    while True:
        # 获取方法对象
        method = globals().get(method_name)
        # 判断方法是否存在
        if not method:
            break
        # 执行方法
        method()
        time.sleep(sleepSecond)  # 等待24小时


async def download_url(session, url, value):
    try:
        async with session.get(url) as resp:
            if resp.status == 200:
                # 如果url有效，将它和值写入m3u文件
                with open('/alive.m3u', 'a') as f:
                    f.write(f'{value}{url}\n')
    except aiohttp.ClientSSLError as ssl_err:
        print(f"SSL Error occurred while downloading {url}: {ssl_err}")
    except Exception as e:
        print(f"Error occurred while downloading {url}: {e}")


async def asynctask(m3u_dict):
    connector = aiohttp.TCPConnector(limit=100)  # 创建 TCP 连接池，限制并发数为 100
    async with aiohttp.ClientSession(connector=connector) as session:  # 将连接池传递给 ClientSession
        # async with aiohttp.ClientSession() as session:
        tasks = []
        for url, value in m3u_dict.items():
            task = asyncio.create_task(download_url(session, url, value))
            tasks.append(task)
        await asyncio.gather(*tasks)


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


def fetch_url(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        m3u_string = response.text
        m3u_string += "\n"
        # print(f"success to fetch URL: {url}")
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


def write_to_file2(data, file):
    with open(file, 'a', encoding='utf-8') as f:
        for line in data:
            f.write(f'{line}\n')


def worker2(queue, file):
    while True:
        data = queue.get()
        if data is None:
            break
        write_to_file2(data, file)
        queue.task_done()


def download_files(urls):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # 提交下载任务并获取future对象列表
        future_to_url = {executor.submit(fetch_url, url): url for url in urls}
        # 获取各个future对象的返回值并存储在字典中
        results = []
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
            except Exception as exc:
                print('%r generated an exception: %s' % (url, exc))
            else:
                results.append(result)
    # 将结果按照原始URL列表的顺序排序并返回它们
    return "".join(results)


# 添加一条数据进入字典
def addlist(request, rediskey):
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    my_dict = {addurl: name}
    redis_add_map(rediskey, my_dict)
    return jsonify({'addresult': "add success"})


def writeTvList():
    distribute_data(white_list_adguardhome, "/tvlist.txt", 10)
    white_list_adguardhome.clear()


def updateAdguardhomeWithelistForM3us(urls):
    for url in urls:
        updateAdguardhomeWithelistForM3u(url.decode("utf-8"))


def chaorongheBase(redisKeyLink, processDataMethodName, redisKeyData, fileName):
    results = redis_get_map_keys(redisKeyLink)
    ism3u = processDataMethodName == 'process_data_abstract'
    if ism3u:
        thread = threading.Thread(target=updateAdguardhomeWithelistForM3us, args=(results,))
        thread.start()
    result = download_files(results)
    # 格式优化
    # my_dict = formattxt_multithread(result.split("\n"), 100)
    my_dict = formattxt_multithread(result.splitlines(), processDataMethodName)
    # my_dict = formattxt_multithread(result.splitlines(), 100)
    if len(my_dict) == 0:
        return "empty"
    old_dict = redis_get_map(redisKeyData)
    my_dict.update(old_dict)
    redis_add_map(redisKeyData, my_dict)
    # 是m3u的情况要维护一下adguardhome
    if ism3u:
        # 同步方法写出全部配置
        thread = threading.Thread(target=writeTvList)
        thread.start()
    # 同步方法写出全部配置
    distribute_data(my_dict, fileName, 10)
    # 异步缓慢检测出有效链接
    # asyncio.run(asynctask(my_dict))
    if ism3u:
        redis_add_map(REDIS_KEY_M3U_EPG_LOGO, CHANNEL_LOGO)
        redis_add_map(REDIS_KEY_M3U_EPG_GROUP, CHANNEL_GROUP)
        thread = threading.Thread(target=check_file, args=(my_dict,))
        thread.start()
    return "result"


def init_db():
    try:
        # 把数据库直播源logo数据导入内存
        CHANNEL_LOGO.update(redis_get_map(REDIS_KEY_M3U_EPG_LOGO))
    except:
        print("no logo in redis")
    try:
        # 把直播源分组数据导入内存
        CHANNEL_GROUP.update(redis_get_map(REDIS_KEY_M3U_EPG_GROUP))
    except:
        print("no group in redis")
    initProxyModel()
    initProxyServer()


# 初始化节点后端服务器
def initProxyServer():
    # 开服时判断是不是初次挂载容器，是的话添加默认配置文件
    models = redis_get_map(REDIS_KEY_PROXIES_SERVER)
    if models and len(models.items()) > 0:
        return
    else:
        try:
            update_dict = {
                "http://127.0.0.1:25500/sub": "本地服务器",
                "http://192.168.5.1:25500/sub": "本地服务器2"}
            redis_add_map(REDIS_KEY_PROXIES_SERVER, update_dict)
            # 设定默认选择的模板
            tmp_dict = {}
            tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = "本地服务器"
            redis_add_map(REDIS_KEY_PROXIES_SERVER_CHOSEN, tmp_dict)
        except:
            pass


# 初始化节点模板
def initProxyModel():
    # 开服时判断是不是初次挂载容器，是的话添加默认配置文件
    models = redis_get_map(REDIS_KEY_PROXIES_MODEL)
    if models and len(models.items()) > 0:
        return
    else:
        try:
            update_dict = {
                "http://127.0.0.1:4395/url/ACL4SSR_Online.ini": "ACL4SSR_Online 默认版 分组比较全(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_AdblockPlus.ini": "ACL4SSR_Online_AdblockPlus 更多去广告(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Full_Google.ini": "ACL4SSR_Online_Full_Google 全分组 重度用户使用 谷歌细分(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Full.ini": "ACL4SSR_Online_Full 全分组 重度用户使用(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Full_MultiMode.ini": "ACL4SSR_Online_Full_MultiMode.ini 全分组 多模式 重度用户使用(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Full_Netflix.ini": "ACL4SSR_Online_Full_Netflix 全分组 重度用户使用 奈飞全量(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Full_NoAuto.ini": "ACL4SSR_Online_Full_NoAuto.ini 全分组 无自动测速 重度用户使用(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Mini.ini": "ACL4SSR_Online_Mini 精简版(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Mini_AdblockPlus.ini": "ACL4SSR_Online_Mini_AdblockPlus.ini 精简版 更多去广告(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Mini_Fallback.ini": "ACL4SSR_Online_Mini_Fallback.ini 精简版 带故障转移(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Mini_MultiCountry.ini": "ACL4SSR_Online_Mini_MultiCountry.ini 精简版 带港美日国家(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Mini_MultiMode.ini": "ACL4SSR_Online_Mini_MultiMode.ini 精简版 自动测速、故障转移、负载均衡(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Mini_NoAuto.ini": "ACL4SSR_Online_Mini_NoAuto.ini 精简版 不带自动测速(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_MultiCountry.ini": "ACL4SSR_Online_MultiCountry 多国分组(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_NoAuto.ini": "ACL4SSR_Online_NoAuto 无自动测速(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_NoReject.ini": "ACL4SSR_Online_NoReject 无广告拦截规则(本地离线模板)",
                "http://127.0.0.1:4395/url/ACL4SSR_Online_Full_AdblockPlus.ini": "ACL4SSR_Online_Full_AdblockPlus 全分组 重度用户使用 更多去广告(本地离线模板)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini": "ACL4SSR_Online 默认版 分组比较全(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_AdblockPlus.ini": "ACL4SSR_Online_AdblockPlus 更多去广告(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_MultiCountry.ini": "ACL4SSR_Online_MultiCountry 多国分组(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoAuto.ini": "ACL4SSR_Online_NoAuto 无自动测速(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoReject.ini": "ACL4SSR_Online_NoReject 无广告拦截规则(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini": "ACL4SSR_Online_Mini 精简版(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_AdblockPlus.ini": "ACL4SSR_Online_Mini_AdblockPlus.ini 精简版 更多去广告(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_NoAuto.ini": "ACL4SSR_Online_Mini_NoAuto.ini 精简版 不带自动测速(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_Fallback.ini": "ACL4SSR_Online_Mini_Fallback.ini 精简版 带故障转移(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini": "ACL4SSR_Online_Mini_MultiMode.ini 精简版 自动测速、故障转移、负载均衡(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiCountry.ini": "ACL4SSR_Online_Mini_MultiCountry.ini 精简版 带港美日国家(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini": "ACL4SSR_Online_Full 全分组 重度用户使用(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_MultiMode.ini": "ACL4SSR_Online_Full_MultiMode.ini 全分组 多模式 重度用户使用(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_NoAuto.ini": "ACL4SSR_Online_Full_NoAuto.ini 全分组 无自动测速 重度用户使用(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_AdblockPlus.ini": "ACL4SSR_Online_Full_AdblockPlus 全分组 重度用户使用 更多去广告(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_Netflix.ini": "ACL4SSR_Online_Full_Netflix 全分组 重度用户使用 奈飞全量(与Github同步)",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_Google.ini": "ACL4SSR_Online_Full_Google 全分组 重度用户使用 谷歌细分(与Github同步)"}
            # update_dict = {unquote("/ACL4SSR_Online_Full_Mannix.ini"): "本地配置"}
            redis_add_map(REDIS_KEY_PROXIES_MODEL, update_dict)
            tmp_dict = {}
            tmp_dict[REDIS_KEY_PROXIES_MODEL_CHOSEN] = "ACL4SSR_Online 默认版 分组比较全(本地离线模板)"
            # 设定默认选择的模板
            redis_add(REDIS_KEY_PROXIES_MODEL_CHOSEN, tmp_dict)
        except:
            pass


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


def distribute_data_proxies(data, file, num_threads):
    length = len(data)
    # 计算每个线程处理的数据大小
    chunk_size = (length + num_threads - 1) // num_threads
    # 将数据切分为若干个块，每个块包含 chunk_size 个代理
    chunks = [data[i:i + chunk_size] for i in range(0, length, chunk_size)]
    # 创建一个任务队列，并向队列中添加任务
    task_queue = queue.Queue()
    for chunk in chunks:
        task_queue.put(chunk)
    # 创建线程池
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker2, args=(task_queue, file))
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


def formattxt_multithread(data, method_name):
    num_threads = min(math.ceil(len(data) / 1000), 100)
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


def updateAdguardhomeWithelistForM3u(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(':')[0] if ':' in parsed_url.netloc else parsed_url.netloc  # 提取IP地址或域名
    if domain.replace('.', '').isnumeric():  # 判断是否为IP地址
        return
    else:
        # 是域名，但不知道是国内还是国外域名
        white_list_adguardhome["@@||" + domain + "^"] = ""
    # 是ip


# 字符串内容处理-m3u
def process_data(data, index, step, my_dict):
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
                    my_dict[searchurl] = update_epg_by_name(name)
                    updateAdguardhomeWithelistForM3u(searchurl)
                    # my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{name}"\n'
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                    updateAdguardhomeWithelistForM3u(searchurl)
            # 匹配格式：频道，url
            elif re.match(r"^[^#].*，(http|rtsp|rtmp)", line):
                name, url = line.split("，", 1)
                searchurl = url
                if searchurl in my_dict.keys():
                    continue
                if name:
                    my_dict[searchurl] = update_epg_by_name(name)
                    updateAdguardhomeWithelistForM3u(searchurl)
                    # my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{name}"\n'
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                    updateAdguardhomeWithelistForM3u(searchurl)
        # http|rtsp|rtmp开始，跳过P2p
        elif not line.encode().startswith(b"P2p"):
            searchurl = line
            if searchurl in my_dict.keys():
                continue
            # 第一行的无名直播
            if i == 0 and index == 0:
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                updateAdguardhomeWithelistForM3u(searchurl)
                continue
            preline = data[i - 1].strip()
            # 没有名字
            if not preline:
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                updateAdguardhomeWithelistForM3u(searchurl)
                continue
            # 不是名字
            if not preline.encode().startswith(b"#EXTINF"):
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}"\n'
                updateAdguardhomeWithelistForM3u(searchurl)
                continue
            # 有裸名字或者#EXTINF开始但是没有tvg-name\tvg-id\group-title
            else:
                # if not any(substring in line for substring in ["tvg-name", "tvg-id", "group-title"]):
                # my_dict[searchurl] = f'{preline}\n'
                my_dict[searchurl] = update_epg(preline)
                updateAdguardhomeWithelistForM3u(searchurl)
                continue


def update_epg_by_name(tvg_name):
    newStr = "#EXTINF:-1 "
    tvg_logo = CHANNEL_LOGO.get(tvg_name)
    if tvg_logo is not None and tvg_logo != "":
        newStr += f'tvg-logo="{tvg_logo}" '
    group_title = CHANNEL_GROUP.get(tvg_name)
    if group_title is not None and group_title != "":
        newStr += f'group-title="{group_title}"  '
    newStr += f'tvg-name="{tvg_name}"\n'
    return newStr


def update_epg(s):
    tvg_name = re.search(r'tvg-name="([^"]+)"', s)
    if tvg_name:
        tvg_name = tvg_name.group(1)
    else:
        last_comma_index = s.rfind(",")
        tvg_name = s[last_comma_index + 1:].strip()
    if tvg_name != "":
        newStr = "#EXTINF:-1 "
        tvg_id = re.search(r'tvg-id="([^"]+)"', s)
        tvg_id = tvg_id.group(1) if tvg_id else ''
        if tvg_id != "":
            newStr += f'tvg-id="{tvg_id}" '
        tvg_logo = re.search(r'tvg-logo="([^"]+)"', s)
        tvg_logo = tvg_logo.group(1) if tvg_logo else ''
        if tvg_logo == "":
            tvg_logo = CHANNEL_LOGO.get(tvg_name)
        if tvg_logo is not None and tvg_logo != "":
            newStr += f'tvg-logo="{tvg_logo}" '
            if tvg_name not in CHANNEL_LOGO:
                CHANNEL_LOGO[tvg_name] = tvg_logo
        group_title = re.search(r'group-title="([^"]+)"', s)
        group_title = group_title.group(1) if group_title else ''
        if group_title == "":
            group_title = CHANNEL_GROUP.get(tvg_name)
        if group_title is not None and group_title != "":
            newStr += f'group-title="{group_title}"  '
            if tvg_name not in CHANNEL_GROUP:
                CHANNEL_GROUP[tvg_name] = group_title
        newStr += f'tvg-name="{tvg_name}"\n'
        return newStr
    else:
        return s


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


# # 节点去重复做不了，数据落库挺麻烦就不做了，节点转配置随缘，应该能命中一些简单的配置
# def download_from_url(url):
#     try:
#         # 下载订阅链接内容
#         response = requests.get(url, timeout=10)
#         if response.status_code == 200:
#             try:
#                 content = base64.b64decode(response.content).decode('utf-8')
#             except:
#                 content = response.content.decode("utf-8")
#         else:
#             return None
#         if content.startswith(
#                 ("ss://", "ssr://", "vmess://", "vless://", "https://", "trojan://", "http://")):
#             temp_dict = []
#             mutil_proxie_methods(content, temp_dict)
#             return temp_dict
#         else:
#             temp_dict = []
#             multi_proxies_yaml(temp_dict, content)
#             return temp_dict
#     except Exception as e:
#         print(f"下载或处理链接 {url} 出错：{e}")
#         return None


# 暂时不考虑自己写节点解析，重复造轮子很累，这个方法暂时不维护了，实际使用时BUG太多了
# def download_proxies(SUBSCRIPTION_URLS):
#     my_dict = []
#     with concurrent.futures.ThreadPoolExecutor(max_workers=len(SUBSCRIPTION_URLS)) as executor:
#         future_to_url = {executor.submit(download_from_url, url): url for url in SUBSCRIPTION_URLS}
#         for future in concurrent.futures.as_completed(future_to_url):
#             url = future_to_url[future]
#             result = future.result()
#             if result is not None and len(result) > 0:
#                 my_dict.extend(result)
#
#     return my_dict


# 随缘节点转换配置
# def mutil_proxie_methods(content, my_dict):
#     # 根据订阅链接格式处理不同类型的节点
#     for proxy_str in content.splitlines():
#         try:
#             proxy_str = proxy_str.strip()
#             if not proxy_str:
#                 continue
#             # 根据代理协议关键字来判断协议类型并解析代理配置
#             if proxy_str.startswith("ss://"):
#                 try:
#                     method, password, server, port = base64.b64decode(proxy_str[5:]).decode().split(":")
#                 except:
#                     method, passwordandserver, port = base64.b64decode(proxy_str[5:]).decode().split(":")
#                     password, server = passwordandserver.split("@")
#                 new_dict = {
#                     'name': proxy_str.split('#')[-1].strip(),
#                     'server': server,
#                     "type": "ss",
#                     'port': port,
#                     'cipher': method or "auto",
#                     'password': password,
#                 }
#                 my_dict.append("- " + json.dumps(new_dict, ensure_ascii=False))
#                 # my_dict.append(f"- {new_dict}\n")
#             # 严格匹配openclash中ssr节点的格式
#             elif proxy_str.startswith("ssr://"):
#                 decoded = base64.b64decode(proxy_str[6:]).decode("utf-8")
#                 parts = decoded.split(":")
#                 server, port, protocol, method, obfs, password_and_params = parts[0], parts[1], parts[2], parts[3], \
#                     parts[
#                         4], parts[5]
#                 password_and_params = password_and_params.split("/?")
#                 password, params = password_and_params[0], password_and_params[1]
#                 params_dict = dict(re.findall(r'(\w+)=([^\&]+)', params))
#                 group = params_dict.get("group", "")
#                 udp = params_dict.get("udp", "true").lower() == "true"
#                 obfs_param = params_dict.get("obfsparam", "")
#                 protocol_param = params_dict.get("protoparam", "")
#                 remarks_base64 = params_dict.get("remarks", "").encode('utf-8')
#                 remarks = base64.b64decode(remarks_base64).decode('utf-8') if remarks_base64 else ""
#                 name = f"{remarks}-[{group}]"
#                 new_dict = {
#                     "name": name,
#                     "server": server,
#                     "type": "ssr",
#                     "port": int(port),
#                     "udp": udp,
#                     "password": password,
#                     "cipher": method,
#                     "protocol": protocol,
#                     "protocol_param": protocol_param,
#                     "obfs": obfs,
#                     "obfs_param": obfs_param
#                 }
#                 my_dict.append("- " + json.dumps(new_dict, ensure_ascii=False))
#             # 严格匹配openclash中vmess节点的格式
#             elif proxy_str.startswith("vmess://"):
#                 vmess_data = base64.urlsafe_b64decode(proxy_str[8:]).decode()
#                 vmess_json = json.loads(vmess_data)
#                 new_dict = {
#                     'server': vmess_json["add"] or vmess_json["address"] or vmess_json["server"] or vmess_json[
#                         "host"] or vmess_json["remote"],
#                     'port': vmess_json["port"] or vmess_json["server_port"],
#                     'alterId': vmess_json["aid"] or vmess_json["alterId"] or "0",
#                     'uuid': vmess_json["id"] or vmess_json["aid"] or vmess_json["uuid"],
#                     'type': "vmess",
#                     'sni': vmess_json["sni"] or vmess_json["host"] or "",
#                     'cipher': vmess_json['cipher'] or vmess_json['method'] or vmess_json['security'] or vmess_json[
#                         'encryption'] or "auto",
#                     'name': vmess_json["ps"] or vmess_json["name"] or vmess_json["remarks"] or "unkown",
#                     'protocol': vmess_json["v"] or "2",
#                     'network': vmess_json["net"] or vmess_json["network"] or "ws",
#                     'ws-path': vmess_json["ws-path"] or vmess_json["path"] or "",
#                     'tls': vmess_json["tls"] or vmess_json["security"] or False,
#                     'skip-cert-verify': vmess_json["skip-cert-verify"] or vmess_json["insecure"] or True,
#                     'udp': vmess_json["udp"] or True,
#                     'ws-opts': vmess_json["ws-opts"] or vmess_json["ws-headers"] or "",
#                 }
#                 my_dict.append("- " + json.dumps(new_dict, ensure_ascii=False))
#             elif proxy_str.startswith("vless://"):
#                 vless_data = base64.urlsafe_b64decode(proxy_str[8:]).decode()
#                 vless_json = json.loads(vless_data)
#                 new_dict = {
#                     'name': vless_json.get('ps', ''),
#                     'server': vless_json['add'],
#                     'server_port': vless_json['port'],
#                     'protocol': vless_json['net'],
#                     'cipher': vless_json['type'],
#                     'password': vless_json['id'],
#                     'plugin': '',
#                     'plugin_opts': {}
#                 }
#                 my_dict.append("- " + json.dumps(new_dict, ensure_ascii=False))
#             elif proxy_str.startswith("https://"):
#                 https_parts = proxy_str.split(":")
#                 server, port = https_parts[1], https_parts[2].split("/")[0]
#                 new_dict = {
#                     'remarks': proxy_str.split('#')[-1].strip(),
#                     'server': server,
#                     'server_port': port,
#                     'protocol': 'http',
#                     'cipher': 'GET',
#                     'password': '',
#                     'plugin': '',
#                     'plugin_opts': {},
#                 }
#                 my_dict.append("- " + json.dumps(new_dict, ensure_ascii=False))
#             elif proxy_str.startswith("trojan://"):
#                 # 解析链接中的各个部分
#                 parsed_link = urlparse(proxy_str)
#                 password = parsed_link.username  # 密码
#                 server = parsed_link.hostname  # 服务器地址
#                 port = parsed_link.port  # 端口号（如果未指定则为 None）
#                 remarks = unquote(parsed_link.fragment)  # 备注信息（需进行 URL 解码）
#                 new_dict = {
#                     "name": remarks,
#                     "server": server,
#                     "type": "trojan",
#                     "port": port or 443,
#                     "password": password,
#                     "udp": True,
#                     "skip-cert-verify": True,
#                 }
#                 my_dict.append("- " + json.dumps(new_dict, ensure_ascii=False))
#             else:
#                 print(f"无法解析代理链接：{proxy_str}")
#         except:
#             pass


# def str_constructor(loader, node):
#     return loader.construct_scalar(node)
#
#
# def dict_constructor(loader, node):
#     data = {}
#     yield data
#     if isinstance(node, yaml.MappingNode):
#         for key_node, value_node in node.value:
#             key = loader.construct_object(key_node)
#             # 如果遇到 `!<str>` 标签，使用自定义的 `str_constructor` 处理
#             if key == "password":
#                 value = loader.construct_scalar(value_node)
#                 data[key] = str_constructor(loader, value_node)
#             else:
#                 value = loader.construct_object(value_node)
#                 data[key] = value
#
#
# def multi_proxies_yaml(my_dict, yaml_data):
#     try:
#         data = yaml.load(yaml_data, Loader=yaml.FullLoader)
#     except:
#         # 特殊标签
#         yaml.add_constructor("!<str>", str_constructor)
#         yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, dict_constructor)
#         # 加载 YAML 数据
#         data = yaml.load(yaml_data, Loader=yaml.FullLoader)
#     if data:
#         # 标准clash代理，提取proxies部分的字典，直接复制不做任何改变
#         if 'proxies' in data:
#             proxies = data['proxies']
#             for proxy in proxies:
#                 my_dict.append("- " + json.dumps(proxy, ensure_ascii=False))
#                 # my_dict.append(f"- {proxy}\n")
#         else:
#             # 直接全部是代理配置字典，随缘提取
#             proxy_list = json.loads(yaml_data)
#             for proxy in proxy_list:
#                 try:
#                     new_dict = {}
#                     for key, value in proxy.items():
#                         if key == "name" or key == "remarks":
#                             new_dict["name"] = value
#                         elif key == "server" or key == "host" or key == "add" or key == "address":
#                             new_dict["server"] = value
#                         elif key == "port" or key == "server_port":
#                             new_dict["port"] = value
#                         elif key == "password":
#                             new_dict["password"] = value
#                         elif key == "type":
#                             new_dict["type"] = value
#                         elif key == "id" or key == "uuid":
#                             new_dict["uuid"] = value
#                         elif key == "cipher" or key == "method" or key == "security":
#                             new_dict["cipher"] = value
#                         elif key == "alterId" or key == "aid":
#                             new_dict["alterId"] = value
#                         elif key == "network" or key == "net":
#                             new_dict["network"] = value
#                         elif key == "flow":
#                             new_dict["flow"] = value
#                         else:
#                             new_dict[key] = value
#                     if 'type' not in new_dict:
#                         new_dict["type"] = get_proxy_type(proxy)
#                     if 'name' not in new_dict:
#                         new_dict["name"] = "unkown"
#                     my_dict.append("- " + json.dumps(new_dict, ensure_ascii=False))
#                 except:
#                     pass
#
#
# def get_proxy_type(node):
#     # 判断节点类型，返回代理类型字符串
#     if "method" in node and "server_port" in node:
#         if "protocol" in node and "obfs" in node:
#             return "ssr"
#         return "ss"
#     elif "addr" in node:
#         if "password" in node:
#             return "trijan"
#         if "aid" in node:
#             return "vmess"
#         return "vless"
#     else:
#         raise ValueError("Unknown proxy type")


def getProxyButton():
    dict = redis_get_map(REDIS_KEY_PROXIES_TYPE)
    if not dict:
        button = "button-1"
        dict = {}
        dict[REDIS_KEY_PROXIES_TYPE] = button
        redis_add(REDIS_KEY_PROXIES_TYPE, dict)
        return button
    return dict[REDIS_KEY_PROXIES_TYPE]


# 获取自己选择的代理服务器文件,要么本地url，要么远程配置url
def getProxyServerChosen():
    # 根据选择的代理配置名字获取代理配置的url
    dict = redis_get_map(REDIS_KEY_PROXIES_SERVER_CHOSEN)
    if dict:
        model = dict[REDIS_KEY_PROXIES_SERVER_CHOSEN]
        models = redis_get_map(REDIS_KEY_PROXIES_SERVER)
        for url, name in models.items():
            if model == name:
                return url
        return URL
    else:
        return URL


# 获取自己选择的代理配置文件,要么本地url，要么远程配置url
def getProxyModelChosen():
    # 根据选择的代理配置名字获取代理配置的url
    dict = redis_get_map(REDIS_KEY_PROXIES_MODEL_CHOSEN)
    if dict:
        model = dict[REDIS_KEY_PROXIES_MODEL_CHOSEN]
        models = redis_get_map(REDIS_KEY_PROXIES_MODEL)
        for url, name in models.items():
            if model == name:
                return url
        return ""
    else:
        return ""


# 代理转换配置字典生成
def generateProxyConfig(urlStr):
    params = {
        "url": urlStr,
        "insert": False,
        "config": getProxyModelChosen()
    }
    button = getProxyButton()
    # Clash新参数
    if button == "button-1":
        params["target"] = "clash"
        params["new_name"] = True
    # ClashR新参数
    elif button == "button-2":
        params["target"] = "clashr"
        params["new_name"] = True
    # Clash
    elif button == "button-3":
        params["target"] = "clash"
    # Surge3
    elif button == "button-4":
        params["target"] = "surge"
        params["ver"] = 3
    # Surge4
    elif button == "button-5":
        params["target"] = "surge"
        params["ver"] = 4
    # Quantumult
    elif button == "button-6":
        params["target"] = "quan"
    # Surfboard
    elif button == "button-7":
        params["target"] = "surfboard"
    # Loon
    elif button == "button-8":
        params["target"] = "loon"
    # SSAndroid
    elif button == "button-9":
        params["target"] = "sssub"
    # V2Ray
    elif button == "button-10":
        params["target"] = "v2ray"
    # ss
    elif button == "button-11":
        params["target"] = "ss"
    # ssr
    elif button == "button-12":
        params["target"] = "ssr"
    # ssd
    elif button == "button-13":
        params["target"] = "ssd"
    # ClashR
    elif button == "button-14":
        params["target"] = "clashr"
    # Surge2
    elif button == "button-15":
        params["target"] = "surge"
        params["ver"] = 2
    # QuantumultX
    elif button == "button-16":
        params["target"] = "quanx"
    return params


def chaorongheProxies(filename):
    redis_dict = r.hgetall(REDIS_KEY_PROXIES_LINK)
    urlStr = ""
    for key in redis_dict.keys():
        if urlStr != "":
            urlStr += "|"
        urlStr += key.decode('utf-8')
    params = generateProxyConfig(urlStr)
    # 本地配置   urllib.parse.quote("/path/to/clash/config_template.yaml"
    # 网络配置   "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini"
    response = requests.get(getProxyServerChosen(), params=params, timeout=360)
    if response.status_code == 200:
        # 订阅成功处理逻辑
        # print(response.text)
        if os.path.exists(filename):
            os.remove(filename)
        with open(filename, 'w'):
            pass
        write_content_to_file(response.content, filename, 10)
        # # 下载 Clash 配置文件
        # with open(filename, 'wb') as f:
        #     f.write(response.content)
        return "result"
    else:
        # 订阅失败处理逻辑
        print("Error:", response.status_code, response.reason)
        return "empty"


# 线程池切分下载的内容写入本地
def write_chunk(chunk, filename, offset):
    with open(filename, 'r+b') as f:
        f.seek(offset)
        f.write(chunk)


def write_file_thread(content, filename, start, end):
    write_chunk(content[start:end], filename, start)


def write_content_to_file(content, filename, num_threads):
    # 计算每个线程要处理的数据块大小
    chunk_size = len(content) // num_threads

    # 创建字节流分割点列表
    points = [i * chunk_size for i in range(num_threads)]
    points.append(len(content))

    # 定义线程任务
    def worker(start, end):
        write_file_thread(content, filename, start, end)

    # 启动多个线程下载和写入数据块
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_tasks = []
        for i in range(num_threads):
            start, end = points[i], points[i + 1]
            future = executor.submit(worker, start, end)
            future_tasks.append(future)

        for future in future_tasks:
            future.result()


def setRandomValueChosen(key1, key2):
    redis_dict = r.hgetall(key1)
    if redis_dict and len(redis_dict.items()) > 0:
        for key, value in redis_dict.items():
            dict = {}
            dict[key2] = value
            redis_add_map(key2, dict)
            return
    else:
        if key1 == REDIS_KEY_PROXIES_SERVER:
            initProxyServer()
        elif key1 == REDIS_KEY_PROXIES_MODEL:
            initProxyModel()


############################################################协议区####################################################


# 选择目标转换的远程配置
@app.route('/chooseProxyModel', methods=['POST'])
def chooseProxyModel():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_MODEL_CHOSEN] = button
    redis_add_map(REDIS_KEY_PROXIES_MODEL_CHOSEN, dict)
    return "success"


# 选择目标转换的远程服务器
@app.route('/chooseProxyServer', methods=['POST'])
def chooseProxyServer():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = button
    redis_add_map(REDIS_KEY_PROXIES_SERVER_CHOSEN, dict)
    return "success"


# 服务器启动时加载选择的配置
@app.route('/getSelectedModel', methods=['GET'])
def getSelectedModel():
    dict = redis_get_map(REDIS_KEY_PROXIES_MODEL_CHOSEN)
    return jsonify({'button': dict[REDIS_KEY_PROXIES_MODEL_CHOSEN]})


# 服务器启动时加载选择的服务器
@app.route('/getSelectedServer', methods=['GET'])
def getSelectedServer():
    dict = redis_get_map(REDIS_KEY_PROXIES_SERVER_CHOSEN)
    return jsonify({'button': dict[REDIS_KEY_PROXIES_SERVER_CHOSEN]})


# 拉取列表-代理模板
@app.route('/reloadProxyModels', methods=['GET'])
def reloadProxyModels():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_SERVER))


# 上传节点后端服务器json文件
@app.route('/upload_json_file10', methods=['POST'])
def upload_json_file10():
    return upload_json(request, REDIS_KEY_PROXIES_SERVER, "/tmp_data10.json")


# 删除全部节点后端服务器配置
@app.route('/removem3ulinks10', methods=['GET'])
def removem3ulinks10():
    redis_del_map(REDIS_KEY_PROXIES_SERVER)
    redis_del_map(REDIS_KEY_PROXIES_SERVER_CHOSEN)
    initProxyServer()
    return "success"


# 导出节点远程订阅配置
@app.route('/download_json_file10', methods=['GET'])
def download_json_file10():
    return download_json_file_base(REDIS_KEY_PROXIES_SERVER, "/app/temp_proxyserverlistlink.json",
                                   "temp_proxyserverlistlink.json")


# 删除节点远程后端服务器订阅
@app.route('/deletewm3u10', methods=['POST'])
def deletewm3u10():
    returnJson = dellist(request, REDIS_KEY_PROXIES_SERVER)
    setRandomValueChosen(REDIS_KEY_PROXIES_SERVER, REDIS_KEY_PROXIES_SERVER_CHOSEN)
    return returnJson


# 添加节点后端订阅
@app.route('/addnewm3u10', methods=['POST'])
def addnewm3u10():
    return addlist(request, REDIS_KEY_PROXIES_SERVER)


# 拉取全部后端服务器配置
@app.route('/getall10', methods=['GET'])
def getall10():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_SERVER))


# 删除全部节点远程配置订阅
@app.route('/removem3ulinks9', methods=['GET'])
def removem3ulinks9():
    redis_del_map(REDIS_KEY_PROXIES_MODEL)
    redis_del_map(REDIS_KEY_PROXIES_MODEL_CHOSEN)
    initProxyModel()
    return "success"


# 导出节点远程订阅配置
@app.route('/download_json_file9', methods=['GET'])
def download_json_file9():
    return download_json_file_base(REDIS_KEY_PROXIES_MODEL, "/app/temp_proxyremotemodellistlink.json",
                                   "temp_proxyremotemodellistlink.json")


# 删除节点远程配置订阅
@app.route('/deletewm3u9', methods=['POST'])
def deletewm3u9():
    returnJson = dellist(request, REDIS_KEY_PROXIES_MODEL)
    setRandomValueChosen(REDIS_KEY_PROXIES_MODEL, REDIS_KEY_PROXIES_MODEL_CHOSEN)
    return returnJson


# 添加节点远程配置订阅
@app.route('/addnewm3u9', methods=['POST'])
def addnewm3u9():
    return addlist(request, REDIS_KEY_PROXIES_MODEL)


# 拉取全部节点订阅远程配置
@app.route('/getall9', methods=['GET'])
def getall9():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_MODEL))


# 上传节点远程配置json文件
@app.route('/upload_json_file9', methods=['POST'])
def upload_json_file9():
    return upload_json(request, REDIS_KEY_PROXIES_MODEL, "/tmp_data9.json")


# 服务器启动时加载选择的节点类型id
@app.route('/getSelectedButtonId', methods=['GET'])
def getSelectedButtonId():
    button = getProxyButton()
    return jsonify({'button': button})


# 选择目标转换的节点类型id
@app.route('/chooseProxy', methods=['POST'])
def chooseProxy():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_TYPE] = button
    redis_add_map(REDIS_KEY_PROXIES_TYPE, dict)
    return "success"


# 删除全部节点订阅
@app.route('/removem3ulinks8', methods=['GET'])
def removem3ulinks8():
    redis_del_map(REDIS_KEY_PROXIES_LINK)
    return "success"


# 删除节点订阅
@app.route('/deletewm3u8', methods=['POST'])
def deletewm3u8():
    return dellist(request, REDIS_KEY_PROXIES_LINK)


# 添加节点订阅
@app.route('/addnewm3u8', methods=['POST'])
def addnewm3u8():
    return addlist(request, REDIS_KEY_PROXIES_LINK)


# 拉取全部节点订阅
@app.route('/getall8', methods=['GET'])
def getall8():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_LINK))


# 导出节点订阅配置
@app.route('/download_json_file8', methods=['GET'])
def download_json_file8():
    return download_json_file_base(REDIS_KEY_PROXIES_LINK, "/app/temp_proxieslistlink.json",
                                   "temp_proxieslistlink.json")


# 全部节点订阅链接超融合
@app.route('/chaoronghe6', methods=['GET'])
def chaoronghe6():
    try:
        return chaorongheProxies('/config.yaml')
    except:
        return "empty"


# 上传节点配置json文件
@app.route('/upload_json_file8', methods=['POST'])
def upload_json_file8():
    return upload_json(request, REDIS_KEY_PROXIES_LINK, "/tmp_data8.json")


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
        return "empty"


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
        return "empty"


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
        return "empty"


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
        return "empty"


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
    distribute_data(my_dict, "/app/temp_m3u.m3u", 10)
    # 发送JSON文件到前端
    return send_file("temp_m3u.m3u", as_attachment=True)


# 手动上传m3u文件把直播源保存到数据库
@app.route('/upload_m3u_file', methods=['POST'])
def upload_m3u_file():
    file = request.files['file']
    # file_content = file.read().decode('utf-8')
    file_content = file.read()
    # file_content = read_file_with_encoding(file)
    my_dict = formatdata_multithread(file_content.splitlines(), 10)
    # my_dict = formattxt_multithread(file_content.splitlines(), 100)
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    return '文件已上传'


# 删除直播源
@app.route('/deletem3udata', methods=['POST'])
def deletem3udata():
    # 获取 HTML 页面发送的 POST 请求参数
    deleteurl = request.json.get('deleteurl')
    r.hdel('localm3u', deleteurl)
    return jsonify({'deletem3udata': "delete success"})


# 添加直播源
@app.route('/addm3udata', methods=['POST'])
def addm3udata():
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
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
    my_dict = formattxt_multithread(m3utext.split("\n"), 'process_data_abstract')
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
        return "empty"


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
    my_dict = formatdata_multithread(file_content.splitlines(), 10)
    # my_dict = formattxt_multithread(file_content.splitlines(), 100)
    # my_dict = formatdata_multithread(file.readlines(), 100)
    distribute_data(my_dict, "/app/tmp.m3u", 10)
    return send_file("tmp.m3u", as_attachment=True)


init_db()

if __name__ == '__main__':
    timer_thread1 = threading.Thread(target=execute, args=('chaoronghe', 86400))
    timer_thread1.start()
    timer_thread2 = threading.Thread(target=execute, args=('chaoronghe2', 86400))
    timer_thread2.start()
    timer_thread3 = threading.Thread(target=execute, args=('chaoronghe3', 86400))
    timer_thread3.start()
    timer_thread4 = threading.Thread(target=execute, args=('chaoronghe4', 86400))
    timer_thread4.start()
    timer_thread5 = threading.Thread(target=execute, args=('chaoronghe5', 86400))
    timer_thread5.start()
    timer_thread6 = threading.Thread(target=execute, args=('chaoronghe6', 10800))
    timer_thread6.start()
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    finally:
        timer_thread1.join()
        timer_thread2.join()
        timer_thread3.join()
        timer_thread4.join()
        timer_thread5.join()
        timer_thread6.join()

import abc
import asyncio
import base64
import secrets
import string
import concurrent
import ipaddress
import json
import math
import os
import queue
import re
# import atexit
# import shutil
# import signal
# import subprocess
import uuid
from functools import wraps
from xml.etree.ElementTree import fromstring

# import psutil
# import subprocess
import threading
import hashlib
import urllib
import zipfile
from concurrent.futures import ThreadPoolExecutor

import execjs
import m3u8 as m3u8
from zhconv import convert
import aiohttp
import aiofiles
import redis
import requests
import time
from urllib.parse import urlparse, quote
# import yaml
from flask import Flask, jsonify, request, send_file, render_template, send_from_directory, \
    after_this_request, redirect

import chardet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from multidict import CIMultiDict

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True  # 实时更新模板文件
app.config['MAX_CONTENT_LENGTH'] = 1000 * 1024 * 1024  # 上传文件最大限制1000 MB
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # 静态文件缓存时间，默认值为 12 小时。可以通过将其设为 0 来禁止浏览器缓存静态文件
app.config['JSONIFY_TIMEOUT'] = 6000  # 设置响应超时时间为 6000 秒

r = redis.Redis(host='localhost', port=22772)

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
# 黑名单下载链接
REDIS_KEY_BLACKLIST_LINK = "blacklistlink"
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
# m3u白名单:关键字,分组
REDIS_KEY_M3U_WHITELIST = "m3uwhitelist"
# m3u白名单:分组,排名
REDIS_KEY_M3U_WHITELIST_RANK = "m3uwhitelistrank"
# m3u黑名单:关键字,
REDIS_KEY_M3U_BLACKLIST = "m3ublacklist"
# 简易DNS域名白名单
REDIS_KEY_DNS_SIMPLE_WHITELIST = "dnssimplewhitelist"
# 简易DNS域名黑名单
REDIS_KEY_DNS_SIMPLE_BLACKLIST = "dnssimpleblacklist"
# 加密订阅密码历史记录,包括当前密码组
REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS = "secretSubscribeHistoryPass"

# 加密订阅密码当前配置
REDIS_KEY_SECRET_PASS_NOW = 'secretpassnow'

redisKeySecretPassNow = {'m3u': '', 'whitelist': '', 'blacklist': '', 'ipv4': '', 'ipv6': '', 'proxy': ''}

# # gitee账号:用户名,仓库名字,path,access Token
REDIS_KEY_GITEE = 'redisKeyGitee'
redisKeyGitee = {'username': '', 'reponame': '', 'path': '', 'accesstoken': ''}

# # github账号:用户名,仓库名字,path,access Token
REDIS_KEY_GITHUB = 'redisKeyGithub'
redisKeyGithub = {'username': '', 'reponame': '', 'path': '', 'accesstoken': ''}

# # webdav账号:ip,端口，用户名，密码，路径,协议(http/https)
REDIS_KEY_WEBDAV = 'redisKeyWebdav'
redisKeyWebDav = {'ip': '', 'port': '', 'username': '', 'password': '', 'path': '', 'agreement': ''}

REDIS_KEY_FUNCTION_DICT = "functiondict"
# 功能开关字典
function_dict = {}

# 白名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
REDIS_KEY_WHITELIST_DATA_SP = "whitelistdatasp"
# 白名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
whitelistSpData = {}

# 黑名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
REDIS_KEY_BLACKLIST_DATA_SP = "blacklistdatasp"
# 黑名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
blacklistSpData = {}

REDIS_KEY_FILE_NAME = "redisKeyFileName"
# 订阅文件名字字典，命名自由化
file_name_dict = {'allM3u': 'allM3u', 'allM3uSecret': 'allM3uSecret', 'aliveM3u': 'aliveM3u', 'healthM3u': 'healthM3u',
                  'tvDomainForAdguardhome': 'tvDomainForAdguardhome',
                  'tvDomainForAdguardhomeSecret': 'tvDomainForAdguardhomeSecret',
                  'whiteListDnsmasq': 'whiteListDnsmasq', 'whiteListDnsmasqSecret': 'whiteListDnsmasqSecret',
                  'whiteListDomian': 'whiteListDomian',
                  'whiteListDomianSecret': 'whiteListDomianSecret',
                  'openclashFallbackFilterDomain': 'openclashFallbackFilterDomain',
                  'openclashFallbackFilterDomainSecret': 'openclashFallbackFilterDomainSecret',
                  'blackListDomain': 'blackListDomain',
                  'blackListDomainSecret': 'blackListDomainSecret', 'ipv4': 'ipv4', 'ipv4Secret': 'ipv4Secret',
                  'ipv6': 'ipv6',
                  'ipv6Secret': 'ipv6Secret', 'proxyConfig': 'proxyConfig', 'proxyConfigSecret': 'proxyConfigSecret',
                  'whitelistDirectRule': 'whitelistDirectRule', 'blacklistProxyRule': 'blacklistProxyRule',
                  'simpleOpenclashFallBackFilterDomain': 'simpleOpenclashFallBackFilterDomain',
                  'simpleblacklistProxyRule': 'simpleblacklistProxyRule', 'simpleDnsmasq': 'simpleDnsmasq',
                  'simplewhitelistProxyRule': 'simplewhitelistProxyRule', 'minTimeout': '5', 'maxTimeout': '30',
                  'maxTimeoutIgnoreLastUUID': '300', 'maxTimeoutIgnoreAllUUID': '3600', 'maxTimeoutTsSeen': '300'
    , 'maxTimeoutTsFree': '300', 'maxTimeoutM3u8Free': '300', 'audioType': 'copy', 'ffmpegThread': '2',
                  'usernameSys': 'admin', 'passwordSys': 'password'}

# 单独导入导出使用一个配置,需特殊处理:{{url:{pass,name}}}
# 下载网络配置并且加密后上传:url+加密密钥+加密文件名字
REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME = 'downloadAndSecretUploadUrlPasswordAndName'
downAndSecUploadUrlPassAndName = {}

# 下载加密网络配置并且解密还原成源文件:加密url+加密密钥+源文件名字
REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME = 'downloadAndDeSecretUrlPasswordAndName'
downAndDeSecUrlPassAndName = {}

# youtube直播源
REDIS_KEY_YOUTUBE = 'redisKeyYoutube'
# youtube直播源地址，频道名字
redisKeyYoutube = {}
# youtube真实m3u8地址
REDIS_KEY_YOUTUBE_M3U = 'redisKeyYoutubeM3u'
# youtube频道名字,真实m3u8地址
redisKeyYoutubeM3u = {}

# bilibili直播源
REDIS_KEY_BILIBILI = 'redisKeyBilibili'
# bilibili直播源地址，频道名字
redisKeyBilili = {}
# bilibili真实m3u8地址
REDIS_KEY_BILIBILI_M3U = 'redisKeyBilibiliM3u'
# bilibili频道名字,真实m3u8地址
redisKeyBililiM3u = {}

# huya直播源
REDIS_KEY_HUYA = 'redisKeyHuya'
# huya直播源地址，频道名字
redisKeyHuya = {}
# huya真实m3u8地址
REDIS_KEY_HUYA_M3U = 'redisKeyHuyaM3u'
# huya频道名字,真实m3u8地址
redisKeyHuyaM3u = {}

# YY直播源
REDIS_KEY_YY = 'redisKeyYY'
# YY直播源地址，频道名字
redisKeyYY = {}
# YY真实m3u8地址
REDIS_KEY_YY_M3U = 'redisKeyYYM3u'
# YY频道名字,真实m3u8地址
redisKeyYYM3u = {}

port_live = 22771


NORMAL_REDIS_KEY = 'normalRedisKey'
# 全部有redis备份字典key-普通redis结构，重要且数据量比较少的
allListArr = [REDIS_KEY_M3U_LINK, REDIS_KEY_WHITELIST_LINK, REDIS_KEY_BLACKLIST_LINK, REDIS_KEY_WHITELIST_IPV4_LINK,
              REDIS_KEY_WHITELIST_IPV6_LINK, REDIS_KEY_PASSWORD_LINK, REDIS_KEY_PROXIES_LINK, REDIS_KEY_PROXIES_TYPE,
              REDIS_KEY_PROXIES_MODEL, REDIS_KEY_PROXIES_MODEL_CHOSEN, REDIS_KEY_PROXIES_SERVER,
              REDIS_KEY_PROXIES_SERVER_CHOSEN, REDIS_KEY_GITEE, REDIS_KEY_GITHUB,
              REDIS_KEY_SECRET_PASS_NOW, REDIS_KEY_WEBDAV, REDIS_KEY_FILE_NAME,
              REDIS_KEY_FUNCTION_DICT, REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS]

# 数据巨大的redis配置,一键导出时单独导出每个配置
hugeDataList = [REDIS_KEY_BILIBILI, REDIS_KEY_DNS_SIMPLE_WHITELIST, REDIS_KEY_DNS_SIMPLE_BLACKLIST, REDIS_KEY_YOUTUBE,
                REDIS_KEY_M3U_WHITELIST_RANK, REDIS_KEY_M3U_BLACKLIST, REDIS_KEY_M3U_WHITELIST, REDIS_KEY_HUYA,
                REDIS_KEY_YY]

SPECIAL_REDIS_KEY = 'specialRedisKey'
specialRedisKey = [REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME,
                   REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME]

# Adguardhome屏蔽前缀
BLACKLIST_ADGUARDHOME_FORMATION = "0.0.0.0 "
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
# 白名单总缓存，数据大量，是全部规则缓存
white_list_nameserver_policy = {}
# DOMAIN-SUFFIX,域名,DIRECT--以该域名结尾的全部直连
white_list_Direct_Rules = {}
# 黑名单总缓存，数据大量，是全部规则缓存
black_list_nameserver_policy = {}
# DOMAIN-SUFFIX,域名,DIRECT--以该域名结尾的全部代理
black_list_Proxy_Rules = {}

# 下载的域名白名单存储到redis服务器里
REDIS_KEY_WHITE_DOMAINS = "whitedomains"
# 下载的域名黑名单存储到redis服务器里
REDIS_KEY_BLACK_DOMAINS = "blackdomains"

# 0-数据未更新 1-数据已更新 max-所有服务器都更新完毕(有max个服务器做负载均衡)
REDIS_KEY_UPDATE_WHITE_LIST_FLAG = "updatewhitelistflag"
REDIS_KEY_UPDATE_BLACK_LIST_FLAG = "updateblacklistflag"
REDIS_KEY_UPDATE_IPV4_LIST_FLAG = "updateipv4listflag"
REDIS_KEY_UPDATE_THREAD_NUM_FLAG = "updatethreadnumflag"
REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG = "updatechinadnsserverflag"
REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG = "updatechinadnsportflag"
REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG = "updateextradnsserverflag"
REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG = "updateextradnsportflag"
REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG = "updatesimplewhitelistflag"
REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG = "updatesimpleblacklistflag"
REDIS_KEY_UPDATE_WHITE_LIST_SP_FLAG = "updatewhitelistspflag"
REDIS_KEY_UPDATE_BLACK_LIST_SP_FLAG = "updateblacklistspflag"

REDIS_KEY_THREADS = "threadsnum"
threadsNum = {REDIS_KEY_THREADS: 1000}

REDIS_KEY_CHINA_DNS_SERVER = "chinadnsserver"
chinadnsserver = {REDIS_KEY_CHINA_DNS_SERVER: ""}

REDIS_KEY_CHINA_DNS_PORT = "chinadnsport"
chinadnsport = {REDIS_KEY_CHINA_DNS_PORT: 0}

REDIS_KEY_EXTRA_DNS_SERVER = "extradnsserver"
extradnsserver = {REDIS_KEY_EXTRA_DNS_SERVER: ""}

REDIS_KEY_EXTRA_DNS_PORT = "extradnsport"
extradnsport = {REDIS_KEY_EXTRA_DNS_PORT: 0}

REDIS_KEY_DNS_QUERY_NUM = "dnsquerynum"
dnsquerynum = {REDIS_KEY_DNS_QUERY_NUM: 0}

REDIS_KEY_DNS_TIMEOUT = "dnstimeout"
dnstimeout = {REDIS_KEY_DNS_TIMEOUT: 0}

REDIS_KEY_IP = "ip"
ip = {REDIS_KEY_IP: ""}


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


def check_auth(username, password):
    usernameSys = getFileNameByTagName('usernameSys')
    passwordSys = getFileNameByTagName('passwordSys')
    if username == usernameSys and password == passwordSys:
        return True
    # 进行用户名和密码验证的逻辑
    # 如果验证通过，返回True；否则返回False
    return False


def authenticate():
    message = {'message': "Authentication failed."}
    resp = jsonify(message)
    resp.status_code = 401
    resp.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
    return resp


# 针对已登录用户的受保护视图函数
@app.route('/')
@requires_auth
def index():
    return render_template('index.html')


# 公共路径，放的全部是加密文件，在公共服务器开放这个路径访问
public_path = '/app/ini/'
# 隐私路径，放的全部是明文文件，在公共服务器不要开放这个路径访问
secret_path = '/app/secret/'


# 路由隐藏真实路径-公共路径
@app.route('/url/<path:filename>')
def serve_files(filename):
    root_dir = public_path  # 根目录
    return send_from_directory(root_dir, filename, as_attachment=True)


# 路由隐藏真实路径-隐私路径
@app.route('/secret/<path:filename>')
def serve_files2(filename):
    root_dir = secret_path  # 根目录
    return send_from_directory(root_dir, filename, as_attachment=True)


# 路由youtube
@app.route('/youtube/<path:filename>')
def serve_files3(filename):
    id = filename.split('.')[0]
    url = redisKeyYoutubeM3u[id]

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response

    return redirect(url)


# 路由bilibili
@app.route('/bilibili/<path:filename>')
def serve_files4(filename):
    id = filename.split('.')[0]
    url = redisKeyBililiM3u[id]

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response

    return redirect(url)


# 路由huya
@app.route('/huya/<path:filename>')
def serve_files5(filename):
    id = filename.split('.')[0]
    url = redisKeyHuyaM3u[id]

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response

    return redirect(url)


# 路由YY
@app.route('/YY/<path:filename>')
def serve_files6(filename):
    id = filename.split('.')[0]
    url = redisKeyYYM3u[id]

    @after_this_request
    def add_header(response):
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response

    return redirect(url)


##############################################################bilibili############################################
async def pingM3u(session, value, real_dict, key, sem, mintimeout, maxTimeout):
    try:
        async with sem, session.get(value, timeout=mintimeout) as response:
            if response.status == 200:
                real_dict[key] = value
    except asyncio.TimeoutError:
        try:
            async with sem, session.get(value, timeout=maxTimeout) as response:
                if response.status == 200:
                    real_dict[key] = value
        except Exception as e:
            pass
    except Exception as e:
        pass


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
    return array, redis_dict


# redis删除map字典
def redis_del_map(key):
    try:
        r.delete(key)
    except Exception as e:
        pass


#########################################################通用工具区#################################################
# 上传订阅配置
def upload_json_base(rediskey, file_content):
    try:
        json_dict = json.loads(file_content)
        if rediskey not in specialRedisKey:
            if rediskey == REDIS_KEY_M3U_WHITELIST:
                dict_final = {}
                for key, value in json_dict.items():
                    dict_final[convert(key, 'zh-tw').lower()] = value
                    dict_final[convert(key, 'zh-cn').lower()] = value
                redis_add_map(rediskey, dict_final)
                importToReloadCache(rediskey, dict_final)
            else:
                redis_add_map(rediskey, json_dict)
                importToReloadCache(rediskey, json_dict)
        else:
            importToReloadCacheForSpecial(rediskey, json_dict)
        return jsonify({'success': True})
    except Exception as e:
        print("An error occurred: ", e)
        return jsonify({'success': False})


def executeProxylist(sleepSecond):
    while True:
        # 执行方法
        chaoronghe6()
        if isOpenFunction('switch35'):
            # 执行方法
            chaoronghe24()
            chaoronghe25()
            chaoronghe26()
            chaoronghe27()
            print("直播源定时器执行成功")
        time.sleep(sleepSecond)


def executeWhitelist(sleepSecond):
    while True:
        if isOpenFunction('switch26'):
            # 执行方法
            chaoronghe2()
        if isOpenFunction('switch13'):
            # 执行方法
            chaoronghe3()
        if isOpenFunction('switch27'):
            # 执行方法
            chaoronghe4()
        if isOpenFunction('switch28'):
            # 执行方法
            chaoronghe5()
        if isOpenFunction('switch33'):
            # 执行方法
            chaoronghe9()
        if isOpenFunction('switch34'):
            # 执行方法
            chaoronghe10()
        time.sleep(sleepSecond)


def toggle_m3u(functionId, value):
    global function_dict
    if functionId == 'switch24':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
        redis_add(REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG, 1)
    elif functionId == 'switch25':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch26':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch13':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch27':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch28':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch33':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch34':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
    elif functionId == 'switch35':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)


def executeM3u(sleepSecond):
    while True:
        if isOpenFunction('switch25'):
            # 执行方法
            chaoronghe()
        time.sleep(sleepSecond)


async def checkWriteHealthM3u(url):
    # 关闭白名单直播源生成
    if not isOpenFunction('switch5'):
        return
    name = tmp_url_tvg_name_dict.get(url)
    if name:
        path2 = f"{secret_path}{getFileNameByTagName('healthM3u')}.m3u"
        async with aiofiles.open(path2, 'a', encoding='utf-8') as f:  # 异步的方式写入内容
            await f.write(f'{name}{url}\n')
        del tmp_url_tvg_name_dict[url]
    else:
        return


async def download_url(session, url, value, sem):
    try:
        async with sem, session.get(url) as resp:  # 使用asyncio.Semaphore限制TCP连接的数量
            if resp.status == 200:
                path = f"{secret_path}{getFileNameByTagName('aliveM3u')}.m3u"
                async with aiofiles.open(path, 'a', encoding='utf-8') as f:  # 异步的方式写入内容
                    await f.write(f'{value}{url}\n')
                await checkWriteHealthM3u(url)
    except aiohttp.ClientSSLError as ssl_err:
        print(f"SSL Error occurred while downloading {url}: {ssl_err}")
    except Exception as e:
        print(f"Error occurred while downloading {url}: {e}")


async def asynctask(m3u_dict):
    sem = asyncio.Semaphore(100)  # 限制TCP连接的数量为100个
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url, value in m3u_dict.items():
            task = asyncio.create_task(download_url(session, url, value, sem))
            tasks.append(task)
        await asyncio.gather(*tasks)


def copyAndRename(source_file):
    with open(source_file, 'rb') as fsrc:
        return fsrc.read()




def check_file(m3u_dict):
    try:
        """
            检查直播源文件是否存在且没有被占用
            """
        # chaoronghe24()
        # chaoronghe25()
        oldChinaChannelDict = redis_get_map(REDIS_KET_TMP_CHINA_CHANNEL)
        if oldChinaChannelDict:
            tmp_url_tvg_name_dict.update(oldChinaChannelDict)
        if len(tmp_url_tvg_name_dict.keys()) > 0:
            redis_add_map(REDIS_KET_TMP_CHINA_CHANNEL, tmp_url_tvg_name_dict)
        path = f"{secret_path}{getFileNameByTagName('aliveM3u')}.m3u"
        if os.path.exists(path):
            os.remove(path)
        path3 = f"{secret_path}youtube.m3u"
        path4 = f"{secret_path}bilibili.m3u"
        path5 = f"{secret_path}huya.m3u"
        path6 = f"{secret_path}YY.m3u"
        source = ''
        if os.path.exists(path3):
            source += copyAndRename(path3).decode()
        if os.path.exists(path4):
            source += '\n'
            source += copyAndRename(path4).decode()
        if os.path.exists(path5):
            source += '\n'
            source += copyAndRename(path5).decode()
        if os.path.exists(path6):
            source += '\n'
            source += copyAndRename(path6).decode()
        with open(path, 'wb') as fdst:
            fdst.write(source.encode('utf-8'))
        path2 = f"{secret_path}{getFileNameByTagName('healthM3u')}.m3u"
        if isOpenFunction('switch5'):
            if os.path.exists(path2):
                os.remove(path2)
            source2 = ''
            if os.path.exists(path3):
                source2 += copyAndRename(path3).decode()
            if os.path.exists(path4):
                source2 += copyAndRename(path4).decode()
            if os.path.exists(path5):
                source2 += copyAndRename(path5).decode()
            if os.path.exists(path6):
                source2 += copyAndRename(path6).decode()
            with open(path2, 'wb') as fdst:
                fdst.write(source2.encode('utf-8'))
            # 异步缓慢检测出有效链接
        if len(m3u_dict) == 0:
            return
        asyncio.run(asynctask(m3u_dict))
    except:
        pass


def checkbytes(url):
    if isinstance(url, bytes):
        return decode_bytes(url).strip()
    else:
        return url


# 判断是否需要解密
def checkToDecrydecrypt(url, redis_dict, m3u_string):
    password = redis_dict.get(url)
    if password:
        password = password.decode()
        if password != "":
            blankContent = decrypt(password, m3u_string)
            return blankContent
    return m3u_string


# 判断是否需要解密
def checkToDecrydecrypt3(url, redis_dict, m3u_string, filenameDict):
    password = redis_dict.get(url)
    if password:
        if password != "":
            blankContent = decrypt(password, m3u_string)
            thread_write_bytes_to_file(filenameDict[url], checkbytes(blankContent).encode())
    else:
        if isinstance(m3u_string, bytes):
            thread_write_bytes_to_file(filenameDict[url], m3u_string)
        else:
            thread_write_bytes_to_file(filenameDict[url], m3u_string.encode())


# 判断是否需要加密
def checkToDecrydecrypt2(url, redis_dict, m3u_string, filenameDict, secretNameDict, uploadGitee,
                         uploadGithub, uploadWebdav):
    password = redis_dict.get(url)
    if password:
        if password != "":
            secretContent = encrypt2(m3u_string, password)
            secretFileName = secretNameDict[url]
            thread_write_bytes_to_file(secretFileName, secretContent)
            # 加密文件上传至gitee,
            if uploadGitee:
                task_queue.put(os.path.basename(secretFileName))
            # 加密文件上传至github,
            if uploadGithub:
                task_queue_github.put(os.path.basename(secretFileName))
            # 加密文件上传至webdav,
            if uploadWebdav:
                task_queue_webdav.put(os.path.basename(secretFileName))
    if isinstance(m3u_string, bytes):
        thread_write_bytes_to_file(filenameDict[url], m3u_string)
    else:
        thread_write_bytes_to_file(filenameDict[url], m3u_string.encode('utf-8'))


def fetch_url(url, redis_dict):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        m3u_string = checkToDecrydecrypt(url, redis_dict, m3u_string)
        # 转换成字符串格式返回
        m3u_string = checkbytes(m3u_string)
        m3u_string += "\n"
        # print(f"success to fetch URL: {url}")
        return m3u_string
    except requests.exceptions.SSLError:
        response = requests.get(url, timeout=5, verify=False)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        m3u_string = checkToDecrydecrypt(url, redis_dict, m3u_string)
        # 转换成字符串格式返回
        m3u_string = checkbytes(m3u_string)
        return m3u_string
    except requests.exceptions.Timeout:
        print("timeout error, try to get data with longer timeout:" + url)
    except requests.exceptions.RequestException as e:
        url = url.decode('utf-8')
        response = requests.get(url, timeout=5, verify=False)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        m3u_string = checkToDecrydecrypt(url, redis_dict, m3u_string)
        # 转换成字符串格式返回
        m3u_string = checkbytes(m3u_string)
        # print(f"success to fetch URL: {url}")
        return m3u_string
        # print("other error: " + url, e)
    except:
        pass


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
    with open(file, 'a', ) as f:
        for line in data:
            f.write(f'{line}')


def worker2(queue, file):
    while True:
        data = queue.get()
        if data is None:
            break
        write_to_file2(data, file)
        queue.task_done()


def download_files(urls, redis_dict):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # 提交下载任务并获取future对象列表
        future_to_url = {executor.submit(fetch_url, url, redis_dict): url for url in urls}
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


def fetch_url2(url, passwordDict, filenameDict, secretNameDict, uploadGitee, uploadGithub, uploadWebdav):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt2(url, passwordDict, m3u_string, filenameDict, secretNameDict, uploadGitee,
                             uploadGithub, uploadWebdav)
    except requests.exceptions.SSLError:
        response = requests.get(url, timeout=5, verify=False)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt2(url, passwordDict, m3u_string, filenameDict, secretNameDict, uploadGitee,
                             uploadGithub, uploadWebdav)
    except requests.exceptions.Timeout:
        print("timeout error, try to get data with longer timeout:" + url)
    except requests.exceptions.RequestException as e:
        url = url.decode('utf-8')
        response = requests.get(url, timeout=5, verify=False)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt2(url, passwordDict, m3u_string, filenameDict, secretNameDict, uploadGitee,
                             uploadGithub, uploadWebdav)
    except Exception as e:
        print("fetch_url2 error:", e)
        pass


def fetch_url3(url, passwordDict, filenameDict):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt3(url, passwordDict, m3u_string, filenameDict)
    except requests.exceptions.SSLError:
        response = requests.get(url, timeout=5, verify=False)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt3(url, passwordDict, m3u_string, filenameDict)
    except requests.exceptions.Timeout:
        print("timeout error, try to get data with longer timeout:" + url)
    except requests.exceptions.RequestException as e:
        url = url.decode('utf-8')
        response = requests.get(url, timeout=5, verify=False)
        response.raise_for_status()  # 如果响应的状态码不是 200，则引发异常
        # 源文件是二进制的AES加密文件，那么通过response.text转换成字符串后，数据可能会被破坏，从而无法还原回原始数据
        m3u_string = response.content
        # 加密文件检测和解码
        checkToDecrydecrypt3(url, passwordDict, m3u_string, filenameDict)
    except Exception as e:
        print("fetch_url3 error:", e)
        pass


#
def download_files2(urls, passwordDict, filenameDict, secretNameDict, uploadGitee, uploadGithub,
                    uploadWebdav):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # 提交下载任务并获取future对象列表
        future_to_url = {
            executor.submit(fetch_url2, url, passwordDict, filenameDict, secretNameDict, uploadGitee,
                            uploadGithub, uploadWebdav): url for
            url in urls}
    # 等待所有任务执行完毕
    executor.shutdown(wait=True)


def download_files3(urls, passwordDict, filenameDict):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # 提交下载任务并获取future对象列表
        future_to_url = {
            executor.submit(fetch_url3, url, passwordDict, filenameDict): url for
            url in urls}
    # 等待所有任务执行完毕
    executor.shutdown(wait=True)


# 添加一条数据进入字典
def addlist(request, rediskey):
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    my_dict = {addurl: name}
    redis_add_map(rediskey, my_dict)
    return jsonify({'addresult': "add success"})


# update 开启m3u域名白名单加密文件上传gitee
# secretfile 开启m3u域名白名单生成加密文件
def writeTvList(fileName, secretfilename):
    distribute_data(white_list_adguardhome, fileName, 10)
    white_list_adguardhome.clear()
    download_secert_file(fileName, secretfilename, 'm3u',
                         isOpenFunction('switch8'), isOpenFunction('switch7'), isOpenFunction('switch30'),
                         isOpenFunction('switch31'), isOpenFunction('switch32'))


# whitelist-加密上传   switch11
# whitelist-加密生成   switch12
def writeOpenclashNameServerPolicy():
    if white_list_nameserver_policy and len(white_list_nameserver_policy) > 0:
        # 更新redis数据库白名单三级分层字典
        redis_del_map(REDIS_KEY_WHITELIST_DATA_SP)
        global whitelistSpData
        redis_add_map(REDIS_KEY_WHITELIST_DATA_SP, whitelistSpData)
        whitelistSpData.clear()
        # 通知dns服务器更新内存
        redis_add(REDIS_KEY_UPDATE_WHITE_LIST_SP_FLAG, 1)
        # redis_add(REDIS_KEY_UPDATE_WHITE_LIST_FLAG, 1)
        # 更新redis数据库白名单
        # redis_add_map(REDIS_KEY_WHITE_DOMAINS, white_list_nameserver_policy)
        path = f"{secret_path}{getFileNameByTagName('whiteListDomian')}.txt"
        distribute_data(white_list_nameserver_policy, path, 10)
        white_list_nameserver_policy.clear()
        path2 = f"{secret_path}{getFileNameByTagName('whitelistDirectRule')}.txt"
        distribute_data(white_list_Direct_Rules, path2, 10)
        white_list_Direct_Rules.clear()

        # 白名单加密
        download_secert_file(path, f"{public_path}{getFileNameByTagName('whiteListDomianSecret')}.txt", 'whitelist',
                             isOpenFunction('switch12'), isOpenFunction('switch11'),
                             isOpenFunction('switch30'), isOpenFunction('switch31'), isOpenFunction('switch32'))


def writeBlackList():
    if black_list_nameserver_policy and len(black_list_nameserver_policy) > 0:
        # 更新redis数据库白名单三级分层字典
        redis_del_map(REDIS_KEY_BLACKLIST_DATA_SP)
        global blacklistSpData
        redis_add_map(REDIS_KEY_BLACKLIST_DATA_SP, blacklistSpData)
        blacklistSpData.clear()
        # 通知dns服务器更新内存
        redis_add(REDIS_KEY_UPDATE_BLACK_LIST_SP_FLAG, 1)

        # 更新redis数据库黑名单
        # redis_add_map(REDIS_KEY_BLACK_DOMAINS, black_list_nameserver_policy)
        # 通知dns服务器更新内存
        # redis_add(REDIS_KEY_UPDATE_BLACK_LIST_FLAG, 1)
        path = f"{secret_path}{getFileNameByTagName('blackListDomain')}.txt"
        distribute_data(black_list_nameserver_policy, path, 10)
        black_list_nameserver_policy.clear()

        path2 = f"{secret_path}{getFileNameByTagName('blacklistProxyRule')}.txt"
        distribute_data(black_list_Proxy_Rules, path2, 10)
        black_list_Proxy_Rules.clear()

        # 黑名单加密
        download_secert_file(path, f"{public_path}{getFileNameByTagName('blackListDomainSecret')}.txt", 'blacklist',
                             isOpenFunction('switch16'),
                             isOpenFunction('switch17'),
                             isOpenFunction('switch30'), isOpenFunction('switch31'), isOpenFunction('switch32'))


def updateAdguardhomeWithelistForM3us(urls):
    for url in urls:
        updateAdguardhomeWithelistForM3u(url.decode("utf-8"))


def chaoronghebase2(redisKeyData, fileName, left1, right1, fileName2, left2):
    old_dict = redis_get_map(redisKeyData)
    if not old_dict or len(old_dict) == 0:
        return "empty"
    newDict = {}
    newDict2 = {}
    for key, value in old_dict.items():
        newDict[left1 + key + right1] = ""
        newDict2[left2 + key] = ''
    # 同步方法写出全部配置
    distribute_data(newDict, fileName, 10)
    distribute_data(newDict2, fileName2, 10)
    return "result"


def fuck_m3u_to_txt(file_path, txt_path):
    # 数据源，字典（词库+新分组名字），新分组名字
    resultContent = m3uToTxt(copyAndRename(file_path).splitlines())
    if os.path.exists(txt_path):
        os.remove(txt_path)
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(resultContent)


def chaorongheBase(redisKeyLink, processDataMethodName, redisKeyData, fileName):
    results, redis_dict = redis_get_map_keys(redisKeyLink)
    ism3u = processDataMethodName == 'process_data_abstract'
    global CHANNEL_LOGO
    global CHANNEL_GROUP
    # 生成直播源域名-无加密
    if ism3u:
        thread = threading.Thread(target=updateAdguardhomeWithelistForM3us, args=(results,))
        thread.start()
        tmp_url_tvg_name_dict.clear()
    result = download_files(results, redis_dict)
    if len(result) > 0:
        # 格式优化
        # my_dict = formattxt_multithread(result.split("\n"), 100)
        my_dict = formattxt_multithread(result.splitlines(), processDataMethodName)
        # my_dict = formattxt_multithread(result.splitlines(), 100)
        if ism3u:
            CHANNEL_LOGO.clear()
            CHANNEL_GROUP.clear()
            CHANNEL_LOGO = redis_get_map(REDIS_KEY_M3U_EPG_LOGO)
            CHANNEL_GROUP = redis_get_map(REDIS_KEY_M3U_EPG_GROUP)
    else:
        if not ism3u:
            return "empty"
        else:
            my_dict = {}
    if len(my_dict) == 0:
        if not ism3u:
            return "empty"
    if ism3u:
        old_dict = redis_get_map(redisKeyData)
        my_dict.update(old_dict)
    else:
        redis_del_map(redisKeyData)
    if ism3u:
        if isOpenFunction('switch4'):
            if len(my_dict) > 0:
                distribute_data(my_dict, fileName, 10)
                fuck_m3u_to_txt(fileName, f"{secret_path}allM3u.txt")
    else:
        # 同步方法写出全部配置
        distribute_data(my_dict, fileName, 10)
    if ism3u:
        if len(my_dict) > 0:
            redis_add_map(redisKeyData, my_dict)
        # M3U域名tvlist - 无加密
        if isOpenFunction('switch6'):
            # 生成直播源域名-无加密
            thread = threading.Thread(target=writeTvList,
                                      args=(f"{secret_path}{getFileNameByTagName('tvDomainForAdguardhome')}.txt",
                                            f"{public_path}{getFileNameByTagName('tvDomainForAdguardhomeSecret')}.txt"))
            thread.start()
        if isOpenFunction('switch'):
            # 神速直播源有效性检测
            thread2 = threading.Thread(target=check_file, args=(my_dict,))
            thread2.start()
        if len(CHANNEL_LOGO) > 0:
            # logo,group更新
            redis_add_map(REDIS_KEY_M3U_EPG_LOGO, CHANNEL_LOGO)
            CHANNEL_LOGO.clear()
        if len(CHANNEL_GROUP) > 0:
            redis_add_map(REDIS_KEY_M3U_EPG_GROUP, CHANNEL_GROUP)
            CHANNEL_GROUP.clear()
        # 开启直播源加密:
        # 加密全部直播源
        thread3 = threading.Thread(target=download_secert_file,
                                   args=(
                                       fileName, f"{public_path}{getFileNameByTagName('allM3uSecret')}.txt", 'm3u',
                                       isOpenFunction('switch2'),
                                       isOpenFunction('switch3'), isOpenFunction('switch30'),
                                       isOpenFunction('switch31'), isOpenFunction('switch32')))
        thread3.start()
        return "result"
    # 域名白名单
    if processDataMethodName == 'process_data_abstract3':
        # whitelist,白名单域名写入redis
        thread = threading.Thread(target=writeOpenclashNameServerPolicy)
        # 生成dnsmasq加密
        thread2 = threading.Thread(target=download_secert_file,
                                   args=(
                                       fileName, f"{public_path}{getFileNameByTagName('whiteListDnsmasqSecret')}.txt",
                                       'whitelist',
                                       isOpenFunction('switch9'), isOpenFunction('switch10'),
                                       isOpenFunction('switch30'), isOpenFunction('switch31'),
                                       isOpenFunction('switch32')))
        thread.start()
        thread2.start()
        return "result"
    # 域名黑名单
    if processDataMethodName == 'process_data_abstract7':
        # blackList.txt
        thread = threading.Thread(target=writeBlackList)
        thread.start()
        # 加密openclash-fallback-filter-domain.conf
        thread2 = threading.Thread(target=download_secert_file,
                                   args=(
                                       fileName,
                                       f"{public_path}{getFileNameByTagName('openclashFallbackFilterDomainSecret')}.txt",
                                       'blacklist',
                                       isOpenFunction('switch14'), isOpenFunction('switch15'),
                                       isOpenFunction('switch30'), isOpenFunction('switch31'),
                                       isOpenFunction('switch32')))
        thread2.start()
        return "result"
    # ipv4
    if processDataMethodName == 'process_data_abstract5':
        # 通知dns服务器更新内存,不给dns分流器使用，数据太大了
        # redis_add(REDIS_KEY_UPDATE_IPV4_LIST_FLAG, 1)
        # ipv4-加密
        thread = threading.Thread(target=download_secert_file,
                                  args=(
                                      fileName, f"{public_path}{getFileNameByTagName('ipv4Secret')}.txt", 'ipv4',
                                      isOpenFunction('switch18'),
                                      isOpenFunction('switch19'), isOpenFunction('switch30'),
                                      isOpenFunction('switch31'), isOpenFunction('switch32')))
        thread.start()
        return "result"
    # ipv6加密
    if processDataMethodName == 'process_data_abstract6':
        # 加密
        thread = threading.Thread(target=download_secert_file,
                                  args=(
                                      fileName, f"{public_path}{getFileNameByTagName('ipv6Secret')}.txt", 'ipv6',
                                      isOpenFunction('switch20'),
                                      isOpenFunction('switch21'), isOpenFunction('switch30'),
                                      isOpenFunction('switch31'), isOpenFunction('switch32')))
        thread.start()
        return "result"
    return "result"


# 纠正url重复/问题
def getCorrectUrl(bakenStr):
    url_parts = bakenStr.split('/')
    cleaned_parts = [part for part in url_parts if part != '']
    cleaned_url = '/'.join(cleaned_parts)
    return cleaned_url


# 检查文件是否已经存在于gitee仓库，存在的话删除旧数据
def removeIfExist(username, repo_name, path, access_token, file_name):
    bakenStr = f'{username}/{repo_name}/contents/{path}/{file_name}'
    url = f'https://gitee.com/api/v5/repos/{getCorrectUrl(bakenStr)}'
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
            print(f'Successfully deleted file {file_name} in GITEE repository.')
        else:
            print(f'Error deleting file {file_name} from GITEE repository.')
        #
        # files = response.json()
        # for file in files:
        #     if file['name'] == file_name:
        #         # Delete the existing file
        #         url = file['url']
        #         sha = file['sha']
        #         message = 'Delete existing file'
        #         data = {'message': message, 'sha': sha}
        #         response = requests.delete(url, headers=headers, json=data)
        #         if response.status_code != 204:
        #             print(f'Failed to delete file. Status code: {response.status_code}')
        #         else:
        #             print('Existing file deleted successfully.')


# 上传新文件到gitee
def uploadNewFileToGitee(username, repo_name, path, access_token, file_name):
    # # 读取要上传的文件内容（bytes比特流）
    with open(f'{public_path}{file_name}', 'rb') as f:
        file_content = f.read()
    # 构建API请求URL和headers
    bakenStr = f'{username}/{repo_name}/contents/{path}/{file_name}'
    url = f'https://gitee.com/api/v5/repos/{getCorrectUrl(bakenStr)}'
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
        print('File uploaded to gitee successfully!')
    else:
        print(f'Failed to upload file to gitee. Status code: {response.status_code}')


def updateFileToGitee(file_name):
    # REDIS_KEY_GITEE
    # redisKeyGitee = {'username': '', 'reponame': '', 'path': '', 'accesstoken': ''}
    global redisKeyGitee
    username = init_gitee('username', REDIS_KEY_GITEE, redisKeyGitee)
    repo_name = init_gitee('reponame', REDIS_KEY_GITEE, redisKeyGitee)
    path = init_gitee('path', REDIS_KEY_GITEE, redisKeyGitee)
    access_token = init_gitee('accesstoken', REDIS_KEY_GITEE, redisKeyGitee)
    now = time.time()
    while time.time() - now < 300:
        try:
            removeIfExist(username, repo_name, path, access_token, file_name)
        except:
            pass
        try:
            uploadNewFileToGitee(username, repo_name, path, access_token, file_name)
            break
        except:
            continue


def removeIfExistGithub(username, repo_name, path, access_token, file_name):
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


def uploadNewFileToGithub(username, repo_name, path, access_token, file_name):
    bakenStr = f'{username}/{repo_name}/contents/{path}/{file_name}'
    url = f'https://api.github.com/repos/{getCorrectUrl(bakenStr)}'
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': f'token {access_token}',
    }
    with open(public_path + file_name, 'rb') as f:
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


def updateFileToGithub(file_name):
    global redisKeyGithub
    username = init_gitee('username', REDIS_KEY_GITHUB, redisKeyGithub)
    repo_name = init_gitee('reponame', REDIS_KEY_GITHUB, redisKeyGithub)
    path = init_gitee('path', REDIS_KEY_GITHUB, redisKeyGithub)
    access_token = init_gitee('accesstoken', REDIS_KEY_GITHUB, redisKeyGithub)
    now = time.time()
    while time.time() - now < 300:
        try:
            removeIfExistGithub(username, repo_name, path, access_token, file_name)
        except:
            pass
        try:
            uploadNewFileToGithub(username, repo_name, path, access_token, file_name)
            break
        except:
            continue


########################webdav##################################

def getAgreement(agreement):
    if "https" in agreement:
        return 'https'
    return 'http'


def purgeAgreement(serverUrl):
    if 'http' in serverUrl:
        return serverUrl.split('//')[1]
    else:
        return serverUrl


# Function to remove a file if it exists in the WebDAV repository
def removeIfExistWebDav(server_url, username, password, base_path, file_name, port, agreement):
    url = f"{purgeAgreement(server_url)}:{port}/{base_path}/{file_name}"
    url = f'{getAgreement(agreement)}://{getCorrectUrl(url)}'
    response = requests.head(url, auth=(username, password))
    if response.status_code == 200:
        response = requests.delete(url, auth=(username, password))
        if response.status_code == 204:
            print(f"Successfully deleted file {file_name} in WebDAV repository.")
    else:
        print(f"File {file_name} does not exist in WebDAV repository, skipping deletion.")


# Function to upload a new file to the WebDAV repository
def uploadNewFileToWebDAV(server_url, username, password, base_path, file_name, port, agreement):
    url = f"{purgeAgreement(server_url)}:{port}/{base_path}/{file_name}"
    url = f'{getAgreement(agreement)}://{getCorrectUrl(url)}'
    with open(public_path + file_name, "rb") as f:
        file_content = f.read()
    response = requests.put(url, auth=(username, password), data=file_content)
    if response.status_code == 201:
        print(f"Successfully uploaded file {file_name} to WebDAV repository.")


def updateFileToWebDAV(file_name):
    global redisKeyWebDav
    username = init_gitee('username', REDIS_KEY_WEBDAV, redisKeyWebDav)
    ip = init_gitee('ip', REDIS_KEY_WEBDAV, redisKeyWebDav)
    port = init_gitee('port', REDIS_KEY_WEBDAV, redisKeyWebDav)
    password = init_gitee('password', REDIS_KEY_WEBDAV, redisKeyWebDav)
    path = init_gitee('path', REDIS_KEY_WEBDAV, redisKeyWebDav)
    agreement = init_gitee('agreement', REDIS_KEY_WEBDAV, redisKeyWebDav)
    now = time.time()
    while time.time() - now < 300:
        try:
            removeIfExistWebDav(ip, username, password, path, file_name, port, agreement)
        except Exception as e:
            # print(e)
            pass
        try:
            uploadNewFileToWebDAV(ip, username, password, path, file_name, port, agreement)
            break
        except Exception as e:
            # print(e)
            continue


# 定义线程数和任务队列,防止多线程提交数据到gitee产生竞争阻塞，最终导致数据丢失
task_queue = queue.Queue()

# 定义线程数和任务队列,防止多线程提交数据到github产生竞争阻塞，最终导致数据丢失
task_queue_github = queue.Queue()

# 定义线程数和任务队列,防止多线程提交数据到webdav产生竞争阻塞，最终导致数据丢失
task_queue_webdav = queue.Queue()


def worker_github():
    while True:
        for i in range(10):
            # 从任务队列中获取一个任务
            if not task_queue_webdav.empty():
                task = task_queue_webdav.get()
                # 执行上传文件操作
                file_name = task
                updateFileToWebDAV(file_name)
        for i in range(10):
            # 从任务队列中获取一个任务
            if not task_queue.empty():
                task = task_queue.get()
                # 执行上传文件操作
                file_name = task
                updateFileToGitee(file_name)
        for i in range(10):
            # 从任务队列中获取一个任务
            if not task_queue_github.empty():
                task = task_queue_github.get()
                # 执行上传文件操作
                file_name = task
                updateFileToGithub(file_name)
        time.sleep(10)


def isOpenFunction(functionId):
    global function_dict
    vaule = function_dict.get(functionId)
    if vaule == '1':
        return True
    else:
        return False


# 把自己本地文件加密生成对应的加密文本
def download_secert_file(fileName, secretFileName, cachekey, openJiaMi, openUpload, uploadGitee,
                         uploadGithub, uploadWebdav):
    try:
        if openJiaMi:
            # 读取文件内容
            with open(fileName, 'rb') as f:
                ciphertext = f.read()
            secretContent = encrypt(ciphertext, cachekey)
            thread_write_bytes_to_file(secretFileName, secretContent)
        # 开启上传
        if openUpload:
            # 加密文件上传至gitee,
            if uploadGitee:
                task_queue.put(os.path.basename(secretFileName))
            # 加密文件上传至github,
            if uploadGithub:
                task_queue_github.put(os.path.basename(secretFileName))
            # 加密文件上传至webdav,
            if uploadWebdav:
                task_queue_webdav.put(os.path.basename(secretFileName))
        # updateFileToGitee(os.path.basename(secretFileName))
        # plaintext = decrypt(password, secretContent)
        # thread_write_bytes_to_file("/解密文件.txt", plaintext)
    except FileNotFoundError:
        print(f"File not found: {fileName}")
    except:
        pass


# 使用线程池把bytes流内容写入本地文件
def thread_write_bytes_to_file(filename, bytesContent):
    if len(bytesContent) == 0:
        return
    if os.path.exists(filename):
        os.remove(filename)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(write_bytes_to_file, filename, bytesContent)
        future.result()
    # 等待所有任务完成
    concurrent.futures.wait([future])


def write_bytes_to_file(filename, plaintext):
    with open(filename, 'wb') as f:
        f.write(plaintext)


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
    init_threads_num()
    init_china_dns_port()
    init_china_dns_server()
    init_extra_dns_server()
    init_extra_dns_port()
    init_m3u_whitelist()
    init_m3u_blacklist()
    init_IP()
    init_pass('proxy')
    init_pass('ipv6')
    init_pass('ipv4')
    init_pass('blacklist')
    init_pass('whitelist')
    init_pass('m3u')
    initReloadCacheForSpecial()
    initReloadCacheForNormal()


def init_function_dict():
    global function_dict
    dict = redis_get_map(REDIS_KEY_FUNCTION_DICT)
    if dict:
        keys = dict.keys()
        # 生成有效M3U
        if 'switch' not in keys:
            dict['switch'] = '1'
        # M3U加密
        if 'switch2' not in keys:
            dict['switch2'] = '0'
        # 完整M3U加密上传
        if 'switch3' not in keys:
            dict['switch3'] = '0'
        # 生成全部M3U
        if 'switch4' not in keys:
            dict['switch4'] = '1'
        # 生成白名单M3U
        if 'switch5' not in keys:
            dict['switch5'] = '1'
        # M3U域名-无加密-tvlist
        if 'switch6' not in keys:
            dict['switch6'] = '1'
        # m3u域名加密文件上传
        if 'switch7' not in keys:
            dict['switch7'] = '0'
        # m3u域名加密文件生成
        if 'switch8' not in keys:
            dict['switch8'] = '0'
        # 域名白名单生成dnsmasq加密文件
        if 'switch9' not in keys:
            dict['switch9'] = '0'
        # dnsmasq加密文件上传
        if 'switch10' not in keys:
            dict['switch10'] = '0'
        # 域名白名单-加密上传
        if 'switch11' not in keys:
            dict['switch11'] = '0'
        # 域名白名单-加密
        if 'switch12' not in keys:
            dict['switch12'] = '0'
        # 域名黑名单-定时器
        if 'switch13' not in keys:
            dict['switch13'] = '1'
        # 域名黑名单-openclash-加密
        if 'switch14' not in keys:
            dict['switch14'] = '0'
        # 域名黑名单-openclash-加密-上传
        if 'switch15' not in keys:
            dict['switch15'] = '0'
        # 域名黑名单-加密
        if 'switch16' not in keys:
            dict['switch16'] = '0'
        # 域名黑名单-加密-上传
        if 'switch17' not in keys:
            dict['switch17'] = '0'
        # ipv4-加密
        if 'switch18' not in keys:
            dict['switch18'] = '0'
        # ipv4-加密-上传
        if 'switch19' not in keys:
            dict['switch19'] = '0'
        # ipv6-加密
        if 'switch20' not in keys:
            dict['switch20'] = '0'
        # ipv6-加密-上传
        if 'switch21' not in keys:
            dict['switch21'] = '0'
        # 节点订阅-加密
        if 'switch22' not in keys:
            dict['switch22'] = '1'
        # 节点订阅+-加密-上传
        if 'switch23' not in keys:
            dict['switch23'] = '1'
        # 自动生成简易DNS黑白名单
        if 'switch24' not in keys:
            dict['switch24'] = '1'
        # m3u-定时器
        if 'switch25' not in keys:
            dict['switch25'] = '0'
        # 域名白名单-定时器
        if 'switch26' not in keys:
            dict['switch26'] = '0'
        # ipv4-定时器
        if 'switch27' not in keys:
            dict['switch27'] = '0'
        # ipv6-定时器
        if 'switch28' not in keys:
            dict['switch28'] = '0'
        # 上传至Gitee
        if 'switch30' not in keys:
            dict['switch30'] = '0'
        # 上传至Github
        if 'switch31' not in keys:
            dict['switch31'] = '0'
        # 上传至Webdav
        if 'switch32' not in keys:
            dict['switch32'] = '0'
        # 下载加密上传-定时器
        if 'switch33' not in keys:
            dict['switch33'] = '0'
        # 下载解密-定时器
        if 'switch34' not in keys:
            dict['switch34'] = '0'
        # YOUTUBE-定时器
        if 'switch35' not in keys:
            dict['switch35'] = '0'
        redis_add_map(REDIS_KEY_FUNCTION_DICT, dict)
        function_dict = dict.copy()
    else:
        dict = {'switch': '1', 'switch2': '0', 'switch3': '0', 'switch4': '1', 'switch5': '1', 'switch6': '1',
                'switch7': '0',
                'switch8': '0', 'switch9': '0', 'switch10': '0', 'switch11': '0', 'switch12': '0', 'switch13': '1',
                'switch14': '0',
                'switch15': '0', 'switch16': '0', 'switch17': '0', 'switch18': '0', 'switch19': '0', 'switch20': '0',
                'switch21': '0',
                'switch22': '1', 'switch23': '1', 'switch24': '1', 'switch25': '0', 'switch26': '0', 'switch27': '0'
            , 'switch28': '0', 'switch30': '0', 'switch31': '0', 'switch32': '0', 'switch33': '0',
                'switch34': '0', 'switch35': '0'}
        redis_add_map(REDIS_KEY_FUNCTION_DICT, dict)
        function_dict = dict.copy()


# 初始化节点后端服务器
def initProxyServer():
    # 开服时判断是不是初次挂载容器，是的话添加默认配置文件
    models = redis_get_map(REDIS_KEY_PROXIES_SERVER)
    if models and len(models.items()) > 0:
        return
    else:
        try:
            update_dict = {
                "http://127.0.0.1:25500/sub": "host模式:本地服务器",
                "http://192.168.5.1:25500/sub": "bridge模式:本地服务器"}
            redis_add_map(REDIS_KEY_PROXIES_SERVER, update_dict)
            # 设定默认选择的模板
            tmp_dict = {}
            tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = "bridge模式:本地服务器"
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
                "http://127.0.0.1:22771/url/ACL4SSR_Online.ini": "ACL4SSR_Online 默认版 分组比较全(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_AdblockPlus.ini": "ACL4SSR_Online_AdblockPlus 更多去广告(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Full_Google.ini": "ACL4SSR_Online_Full_Google 全分组 重度用户使用 谷歌细分(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Full.ini": "ACL4SSR_Online_Full 全分组 重度用户使用(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Full_MultiMode.ini": "ACL4SSR_Online_Full_MultiMode.ini 全分组 多模式 重度用户使用(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Full_Netflix.ini": "ACL4SSR_Online_Full_Netflix 全分组 重度用户使用 奈飞全量(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Full_NoAuto.ini": "ACL4SSR_Online_Full_NoAuto.ini 全分组 无自动测速 重度用户使用(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Mini.ini": "ACL4SSR_Online_Mini 精简版(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Mini_AdblockPlus.ini": "ACL4SSR_Online_Mini_AdblockPlus.ini 精简版 更多去广告(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Mini_Fallback.ini": "ACL4SSR_Online_Mini_Fallback.ini 精简版 带故障转移(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Mini_MultiCountry.ini": "ACL4SSR_Online_Mini_MultiCountry.ini 精简版 带港美日国家(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Mini_MultiMode.ini": "ACL4SSR_Online_Mini_MultiMode.ini 精简版 自动测速、故障转移、负载均衡(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Mini_NoAuto.ini": "ACL4SSR_Online_Mini_NoAuto.ini 精简版 不带自动测速(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_MultiCountry.ini": "ACL4SSR_Online_MultiCountry 多国分组(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_NoAuto.ini": "ACL4SSR_Online_NoAuto 无自动测速(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_NoReject.ini": "ACL4SSR_Online_NoReject 无广告拦截规则(本地离线模板)",
                "http://127.0.0.1:22771/url/ACL4SSR_Online_Full_AdblockPlus.ini": "ACL4SSR_Online_Full_AdblockPlus 全分组 重度用户使用 更多去广告(本地离线模板)",
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
            redis_add_map(REDIS_KEY_PROXIES_MODEL_CHOSEN, tmp_dict)
        except:
            pass


# 多线程写入
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
    if len(data) == 0:
        return
    if os.path.exists(file):
        os.remove(file)
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
    num_threads = 10
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


PROXY_RULE_LEFT = 'DOMAIN-SUFFIX,'
PROXY_RULE_RIGHT = ',PROXY'


def updateBlackList(url):
    black_list_nameserver_policy[url] = ""
    black_list_Proxy_Rules[PROXY_RULE_LEFT + url] = ''


def updateBlackListSpData(domain):
    # 一级域名，类似:一级域名名字.顶级域名名字
    domain_name_str = stupidThink(domain)
    if domain_name_str != '':
        global blacklistSpData
        blacklistSpData[domain_name_str] = ''


def updateBlackListSpDataExtra(domain):
    domain_name_str = stupidThinkForChina(domain)
    if domain_name_str != '':
        global blacklistSpData
        blacklistSpData[domain_name_str] = ''


# 字符串内容处理-域名转openclash-fallbackfilter-domain
# openclash-fallback-filter-domain 填写需要代理的域名
# 可以使用通配符*,但是尽可能少用，可能出问题
def process_data_domain_openclash_fallbackfilter(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # dns分流需要的外国域名一级数据
        updateBlackListSpData(line)
        updateBlackListSpDataExtra(line)
        # 判断是不是+.域名
        lineEncoder = line.encode()
        if re.match(wildcard_regex2, line):
            # 外国域名+第三方规则-外国域名关键字
            updateBlackList((lineEncoder.substring(2)).decode())
            # my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            # my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "*." + (
            #     lineEncoder.substring(2)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + (
                lineEncoder.substring(2)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
        # 判断是不是域名
        elif re.match(domain_regex, line):
            # 全部使用通配符+.可以匹配所有子域名包括自身，适合openclash-fallback-filter配置外国域名组
            my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            if not lineEncoder.startswith(b"www"):
                # 自用dns分流器外国域名，只取最高父域名
                updateBlackList(line)
                # my_dict[
                #     OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
                # my_dict[
                #     OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "*." + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            else:
                updateBlackList((lineEncoder.substring(4)).decode())
                my_dict[
                    OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + (
                        lineEncoder.substring(4)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
                # my_dict[
                #     OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "*." + (
                #         lineEncoder.substring(4)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
        # 判断是不是*.域名
        elif re.match(wildcard_regex, line):
            updateBlackList((lineEncoder.substring(2)).decode())
            # my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            my_dict[
                OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + (
                    lineEncoder.substring(2)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
        elif lineEncoder.startswith(b"."):
            updateBlackList((lineEncoder.substring(1)).decode())
            my_dict[
                OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + (
                    lineEncoder.substring(1)).decode() + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""
            # my_dict[OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT + "*" + line + OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT] = ""


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
        # 判断是ipv4
        if is_ipv4_network(line):
            my_dict[line] = ""
            # 转换成ipv4-整数数组字典
            # update_ipv4_int_range(line)


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


# 黑白名单最大取到二级域名，防止数据太多
def updateWhiteListSpData(domain):
    # 二级域名, 一级域名，类似:一级域名名字.顶级域名名字
    domain_name_str = stupidThink(domain)
    if domain_name_str != '':
        global whitelistSpData
        whitelistSpData[domain_name_str] = ''


# 大陆白名单可以放宽条件把一级域名的情况也放行，但是要剔除一级域名使用顶级域名的情况
def updateWhiteListSpDataForChina(domain):
    domain_name_str = stupidThinkForChina(domain)
    if domain_name_str != '':
        global whitelistSpData
        whitelistSpData[domain_name_str] = ''


# 字符串内容处理-域名转dnsmasq白名单
# openclash dnsmasq不支持+，支持*.和.
# 最简单的做法是*域名*
# 第三方规则不支持+,支持*.和.
# openclash域名白名单全部使用*.域名
def process_data_domain_dnsmasq(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        line = data[i].strip()
        if not line:
            continue
        # dns分流使用的域名白名单
        updateWhiteListSpData(line)
        updateWhiteListSpDataForChina(line)
        # 普通域名
        if re.match(domain_regex, line):
            lineEncoder = line.encode()
            # www域名
            if lineEncoder.startswith(b"www."):
                # 大陆域名白名单+第三方规则直连生成
                updateOpenclashNameServerPolicy((lineEncoder.substring(4)).decode())
                # openclash-dnsmasq域名全部使用通配符*.，用于直接筛查大陆域名
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + '*.' + (
                    lineEncoder.substring(4)).decode() + BLACKLIST_DNSMASQ_FORMATION_right] = ""
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + (
                    lineEncoder.substring(4)).decode() + BLACKLIST_DNSMASQ_FORMATION_right] = ""
            else:
                updateOpenclashNameServerPolicy(line)
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""
                my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + '*.' + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""
        # *.域名
        elif re.match(wildcard_regex, line):
            lineEncoder = line.encode()
            updateOpenclashNameServerPolicy((lineEncoder.substring(2)).decode())
            my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + (
                lineEncoder.substring(2)).decode() + BLACKLIST_DNSMASQ_FORMATION_right] = ""
            my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + line + BLACKLIST_DNSMASQ_FORMATION_right] = ""

        # +.域名
        elif re.match(wildcard_regex2, line):
            lineEncoder = line.encode()
            updateOpenclashNameServerPolicy((lineEncoder.substring(2)).decode())
            my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + (
                lineEncoder.substring(2)).decode() + BLACKLIST_DNSMASQ_FORMATION_right] = ""
            my_dict[BLACKLIST_DNSMASQ_FORMATION_LEFT + '*' + (
                lineEncoder.substring(2)).decode() + BLACKLIST_DNSMASQ_FORMATION_right] = ""


DIRECT_RULE_LEFT = 'DOMAIN-SUFFIX,'
DIRECT_RULE_RIGHT = ',DIRECT'


def updateOpenclashNameServerPolicy(url):
    white_list_nameserver_policy[url] = ""
    white_list_Direct_Rules[DIRECT_RULE_LEFT + url] = ''


def updateAdguardhomeWithelistForM3u(url):
    # 没有开启tvlist生成
    if not isOpenFunction('switch6'):
        return
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(':')[0] if ':' in parsed_url.netloc else parsed_url.netloc  # 提取IP地址或域名
    if domain.replace('.', '').isnumeric():  # 判断是否为IP地址
        return
    else:
        # 是域名，但不知道是国内还是国外域名
        white_list_adguardhome["@@||" + domain + "^"] = ""
    # 是ip


# 自动编码格式检测转换
def decode_text(text):
    try:
        # detect encoding of the string
        result = chardet.detect(text)
        # decode the string using detected encoding
        decoded_text = text.decode(result['encoding']).strip()
        return decoded_text
    except (UnicodeDecodeError, KeyError):
        pass

    try:
        result = text.encode('ascii').decode('utf-8', 'ignore')
        return result
    except UnicodeEncodeError:
        pass

    try:
        result = text.encode('cp936').decode('utf-8', 'ignore')
        return result
    except UnicodeEncodeError:
        pass

    try:
        decoded_text = text.decode('utf-8')
        return decoded_text
    except UnicodeDecodeError:
        pass

    try:
        decoded_text = text.decode('gbk')
        return decoded_text
    except UnicodeDecodeError:
        pass


def decode_bytes(text):
    # define a list of possible encodings
    encodings = ['utf-8', 'gbk', 'iso-8859-1', 'ascii', 'cp936', 'big5', 'shift_jis', 'koi8-r']

    # try each encoding until one works
    for encoding in encodings:
        try:
            return text.decode(encoding).strip()
        except (TypeError, UnicodeDecodeError):
            continue

    # if none of the above worked, use chardet to detect the encoding
    result = chardet.detect(text)
    decoded_text = text.decode(result['encoding']).strip()
    return decoded_text


def pureUrl(s):
    result = s.split('$', 1)[0]
    return result


# m3u转换txt
def m3uToTxt(lines):
    result = []
    # 组名,频道名字,url
    group = {}
    url_dict = {}
    for i in range(len(lines)):
        line = decode_bytes(lines[i]).strip()
        if line == '':
            continue
        # 假定直播名字和直播源不在同一行
        if line.startswith("#EXTINF"):
            continue
        if not line.startswith(("http", "rtsp", "rtmp", 'P2p', 'mitv')):
            continue
        # http开始
        else:
            searchurl = pureUrl(line)
            if searchurl in url_dict.keys():
                continue
            # 第一行的无名直播
            if i == 0 and index == 0:
                continue
            preline = decode_bytes(lines[i - 1]).strip()
            # 没有名字
            if not preline:
                continue
            # 不是名字
            if not preline.startswith("#EXTINF"):
                continue
            try:
                last_comma_index = preline.rfind(",")
                if last_comma_index == -1:
                    raise ValueError("字符串中不存在逗号")
                tvg_name = preline[last_comma_index + 1:].strip()
            except Exception as e:
                try:
                    tvg_name = re.search(r'tvg-name="([^"]+)"', preline)
                    if tvg_name is None:
                        raise ValueError("未找到 tvg-name 属性")
                    tvg_name = tvg_name.group(1)
                except Exception as e:
                    continue
            group_title = re.search(r'group-title="([^"]+)"', preline)
            group_title = group_title.group(1) if group_title else ''
            if group_title == "":
                group_title = '未分组'
            url_dict[searchurl] = ''
            if group_title not in group.keys():
                group[group_title] = tvg_name + ',' + searchurl
            else:
                group[group_title] = group[group_title] + '\n' + tvg_name + ',' + searchurl
    for groupName, nameDict in group.items():
        result.append(f'{groupName},#genre#')
        result.append(f'{nameDict}')
    return '\n'.join(result)


# 数据源，字典（词库+新分组名字），新分组名字
def find_m3u_name_txt(lines, name_dict, def_group):
    for line in lines:
        line = decode_bytes(line).strip()
        if line == '':
            continue
        if not line.startswith(("http", "rtsp", "rtmp", 'P2p', 'mitv')):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,(http|rtsp|rtmp|P2p|mitv)", line):
                name, url = getChannelAndUrl(",", line)
                if name:
                    name_dict[convert(name, 'zh-tw')] = def_group
                    name_dict[convert(name, 'zh-cn')] = def_group
                else:
                    continue
            elif re.match(r"^[^#].*，(http|rtsp|rtmp|P2p|mitv)", line):
                name, url = getChannelAndUrl("，", line)
                if name:
                    name_dict[convert(name, 'zh-tw')] = def_group
                    name_dict[convert(name, 'zh-cn')] = def_group
                else:
                    continue
            else:
                continue
        else:
            continue


# 上传m3u文件bytes格式规整
def format_data(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        # print(type(data[i]))
        line = decode_bytes(data[i]).strip()
        if not line:
            continue
        # 假定直播名字和直播源不在同一行
        if line.startswith("#EXTINF"):
            continue
        if jumpBlackM3uList(line):
            continue
        # 不是http开头，可能是直播源
        if not line.startswith(("http", "rtsp", "rtmp")):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,(http|rtsp|rtmp)", line):
                name, url = getChannelAndUrl(",", line)
                searchurl = pureUrl(url)
                if searchurl in my_dict.keys():
                    continue
                if name:
                    name = name.lower()
                    fullName = update_epg_by_name(name)
                    my_dict[searchurl] = fullName
                    addChinaChannel(name, searchurl, fullName)
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
            elif re.match(r"^[^#].*，(http|rtsp|rtmp)", line):
                name, url = getChannelAndUrl("，", line)
                searchurl = pureUrl(url)
                if searchurl in my_dict.keys():
                    continue
                if name:
                    name = name.lower()
                    fullName = update_epg_by_name(name)
                    my_dict[searchurl] = fullName
                    addChinaChannel(name, searchurl, fullName)
                else:
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
        # http开始
        else:
            # 去重复
            searchurl = pureUrl(line)
            if searchurl in my_dict.keys():
                continue
            # 第一行的无名直播
            if i == 0 and index == 0:
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                continue
            preline = decode_bytes(data[i - 1]).strip()
            # preline = data[i - 1].decode("utf-8").strip()
            # 没有名字
            if not preline:
                my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                continue
            # 不是名字
            if not preline.startswith("#EXTINF"):
                try:
                    last_comma_index = preline.rfind(",")
                    if last_comma_index == -1:
                        raise ValueError("字符串中不存在逗号")
                    tvg_name = preline[last_comma_index + 1:].strip().lower()
                    fullName = update_epg_by_name(tvg_name)
                    my_dict[searchurl] = fullName
                    addChinaChannel(tvg_name, searchurl, fullName)
                except Exception as e:
                    tvg_name = defalutname
                    my_dict[searchurl] = f'#EXTINF:-1  tvg-name="{tvg_name}",{tvg_name}\n'
                continue
            # 有名字
            else:
                my_dict[searchurl] = update_epg_nope(preline)
                continue


# url,tvg-name
tmp_url_tvg_name_dict = {}
REDIS_KET_TMP_CHINA_CHANNEL = 'tmpChinaChannel'


def addChinaChannel(tvg_name, url, fullName):
    # 关闭有效直播源生成
    if not isOpenFunction('switch'):
        return
    # 关闭白名单直播源生成
    if not isOpenFunction('switch5'):
        return
    for name in m3u_whitlist.keys():
        if name in tvg_name:
            tmp_url_tvg_name_dict[url] = fullName
            return


def jumpBlackM3uList(tvg_name):
    for name in m3u_blacklist.keys():
        if name in tvg_name:
            return True
    return False


def getChannelAndUrl(split, str):
    arr = str.split(split)
    length = len(arr)
    if length == 2:
        return arr[0], arr[1]
    name = ''
    for i in range(0, length - 2):
        name += arr[i]
    return name, arr[length - 1]


# 超融合-直播源字符串内容处理-m3u
def process_data(data, index, step, my_dict):
    end_index = min(index + step, len(data))
    for i in range(index, end_index):
        # print(type(data[i]))
        line = data[i].strip()
        # 空行
        if not line:
            continue
        lineEncoder = line.encode()
        line = decode_bytes(lineEncoder).strip()
        # 假定直播名字和直播源不在同一行，跳过频道名字
        if lineEncoder.startswith(b"#EXTINF"):
            continue
        if jumpBlackM3uList(line):
            continue
        # 不是http开头，也可能是直播源
        if not lineEncoder.startswith((b"http", b"rtsp", b"rtmp")):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,(http|rtsp|rtmp)", line):
                name, url = getChannelAndUrl(",", line)
                searchurl = pureUrl(url)
                if searchurl in my_dict.keys():
                    continue
                if name:
                    name = name.lower()
                    fullName = update_epg_by_name(name)
                    my_dict[searchurl] = fullName
                    addChinaChannel(name, searchurl, fullName)
                    updateAdguardhomeWithelistForM3u(searchurl)
                else:
                    fullName = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                    my_dict[searchurl] = fullName
                    updateAdguardhomeWithelistForM3u(searchurl)
            # 匹配格式：频道，url
            elif re.match(r"^[^#].*，(http|rtsp|rtmp)", line):
                name, url = getChannelAndUrl("，", line)
                searchurl = pureUrl(url)
                if searchurl in my_dict.keys():
                    continue
                if name:
                    name = name.lower()
                    fullName = update_epg_by_name(name)
                    my_dict[searchurl] = fullName
                    addChinaChannel(name, searchurl, fullName)
                    updateAdguardhomeWithelistForM3u(searchurl)
                else:
                    fullName = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                    my_dict[searchurl] = fullName
                    updateAdguardhomeWithelistForM3u(searchurl)
        # http|rtsp|rtmp开始，跳过P2p
        elif not lineEncoder.startswith(b"P2p"):
            searchurl = pureUrl(line)
            if searchurl in my_dict.keys():
                continue
            # 第一行的无名直播
            if i == 0 and index == 0:
                fullName = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                my_dict[searchurl] = fullName
                updateAdguardhomeWithelistForM3u(searchurl)
                continue
            preline = data[i - 1].strip()
            prelineEncoder = preline.encode()
            preline = decode_bytes(prelineEncoder).strip()
            # 没有名字
            if not preline:
                fullName = f'#EXTINF:-1  tvg-name="{defalutname}",{defalutname}\n'
                my_dict[searchurl] = fullName
                updateAdguardhomeWithelistForM3u(searchurl)
                continue
            # 不是名字
            if not prelineEncoder.startswith(b"#EXTINF"):
                try:
                    last_comma_index = preline.rfind(",")
                    if last_comma_index == -1:
                        raise ValueError("字符串中不存在逗号")
                    tvg_name = preline[last_comma_index + 1:].strip().lower()
                    fullName = update_epg_by_name(tvg_name)
                    addChinaChannel(tvg_name, searchurl, fullName)
                except Exception as e:
                    tvg_name = defalutname
                    fullName = f'#EXTINF:-1  tvg-name="{tvg_name}",{tvg_name}\n'
                my_dict[searchurl] = fullName
                updateAdguardhomeWithelistForM3u(searchurl)
                continue
            # 有裸名字或者#EXTINF开始但是没有tvg-name\tvg-id\group-title
            else:
                # if not any(substring in line for substring in ["tvg-name", "tvg-id", "group-title"]):
                # my_dict[searchurl] = f'{preline}\n'
                my_dict[searchurl] = update_epg(preline, searchurl)
                updateAdguardhomeWithelistForM3u(searchurl)
                continue


# 已经排序的直播源分组名单,关键字，分组
ranked_m3u_whitelist_set = []


def getRankWhiteList():
    global m3u_whitlist_rank
    global m3u_whitlist
    global ranked_m3u_whitelist_set
    ranked_m3u_whitelist_set.clear()
    ranked_m3u_whitelist = {}
    restSetDict = {}
    for key, value in m3u_whitlist.items():
        if value not in m3u_whitlist_rank.keys():
            restSetDict[key] = value
        if value == '':
            restSetDict[key] = value
    for group, rank in m3u_whitlist_rank.items():
        if group not in m3u_whitlist.values():
            continue
        if group == '':
            continue
        rank = int(rank)
        dict = {}
        for key, value in m3u_whitlist.items():
            if value == group:
                dict[key] = value
        ranked_m3u_whitelist[rank] = dict
    seta = sorted(ranked_m3u_whitelist.keys())  # 对字典的键进行排序
    for key in seta:
        ranked_m3u_whitelist_set.append(ranked_m3u_whitelist[key])  # 将排序后的值依次添加到有序集合中
    ranked_m3u_whitelist_set.append(restSetDict)


# 获取白名单分组
def getMyGroup(str):
    try:
        for dict in ranked_m3u_whitelist_set:
            for key, group in dict.items():
                if key in str:
                    return group
    except Exception as e:
        print(e)
    return ''


def update_epg_by_name(tvg_name):
    newStr = "#EXTINF:-1 "
    group_title = getMyGroup(tvg_name)
    if group_title == '':
        group_title = CHANNEL_GROUP.get(tvg_name)
    if group_title is not None and group_title != "":
        newStr += f'group-title="{group_title}"  '
        if tvg_name not in CHANNEL_GROUP:
            CHANNEL_GROUP[tvg_name] = group_title
    tvg_logo = CHANNEL_LOGO.get(tvg_name)
    if tvg_logo is not None and tvg_logo != "":
        newStr += f'tvg-logo="{tvg_logo}" '
    newStr += f'tvg-name="{tvg_name}",{tvg_name}\n'
    return newStr


def update_epg_nope(s):
    try:
        last_comma_index = s.rfind(",")
        if last_comma_index == -1:
            raise ValueError("字符串中不存在逗号")
        tvg_name = s[last_comma_index + 1:].strip().lower()
    except Exception as e:
        try:
            tvg_name = re.search(r'tvg-name="([^"]+)"', s)
            if tvg_name is None:
                raise ValueError("未找到 tvg-name 属性")
            tvg_name = tvg_name.group(1).lower()
        except Exception as e:
            # 处理异常
            tvg_name = ""
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
        group_title = getMyGroup(s)
        if group_title == '':
            group_title = re.search(r'group-title="([^"]+)"', s)
            group_title = group_title.group(1) if group_title else ''
        if group_title == "":
            group_title = CHANNEL_GROUP.get(tvg_name)
        if group_title is not None and group_title != "":
            newStr += f'group-title="{group_title}"  '
            if tvg_name not in CHANNEL_GROUP:
                CHANNEL_GROUP[tvg_name] = group_title
        newStr += f'tvg-name="{tvg_name}",{tvg_name}\n'
        return newStr
    else:
        return f'{s}\n'


def update_epg(s, searchurl):
    try:
        last_comma_index = s.rfind(",")
        if last_comma_index == -1:
            raise ValueError("字符串中不存在逗号")
        tvg_name = s[last_comma_index + 1:].strip().lower()
    except Exception as e:
        try:
            tvg_name = re.search(r'tvg-name="([^"]+)"', s)
            if tvg_name is None:
                raise ValueError("未找到 tvg-name 属性")
            tvg_name = tvg_name.group(1).lower()
        except Exception as e:
            # 处理异常
            tvg_name = ""
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
        group_title = getMyGroup(s)
        if group_title == '':
            group_title = re.search(r'group-title="([^"]+)"', s)
            group_title = group_title.group(1) if group_title else ''
        if group_title == "":
            group_title = CHANNEL_GROUP.get(tvg_name)
        if group_title is not None and group_title != "":
            newStr += f'group-title="{group_title}"  '
            if tvg_name not in CHANNEL_GROUP:
                CHANNEL_GROUP[tvg_name] = group_title
        newStr += f'tvg-name="{tvg_name}",{tvg_name}\n'
        addChinaChannel(tvg_name, searchurl, newStr)
        return newStr
    else:
        addChinaChannel(defalutname, searchurl, f'{s}\n')
        return f'{s}\n'


def generate_json_string(mapname):
    if mapname not in specialRedisKey:
        m3ulink = redis_get_map(mapname)
    else:
        # 从Redis中读取JSON字符串
        m3ulink = r.get(mapname)
        m3ulink = json.loads(m3ulink)
    # 将字典转换为JSON字符串并返回
    json_str = json.dumps(m3ulink)
    return json_str


# 一键导出全部json配置
def generate_multi_json_string(mapnameArr):
    finalDict = {}
    # 普通python字典结构统一转换成对应的redis结构
    for name in mapnameArr:
        m3ulink = redis_get_map(name)
        if len(m3ulink.keys()) > 0:
            finalDict[name] = m3ulink
    outDict1 = {}
    outDict1[NORMAL_REDIS_KEY] = finalDict

    # 特殊python字典结构存入redis统一转换成string
    finalDict2 = {}
    for name in specialRedisKey:
        try:
            # 从Redis中读取JSON字符串
            json_string_redis = r.get(name)
            # 反序列化成Python对象
            my_dict_redis = json.loads(json_string_redis)
            if len(my_dict_redis.keys()) > 0:
                finalDict2[name] = my_dict_redis
        except Exception as e:
            pass
    outDict2 = {}
    outDict2[SPECIAL_REDIS_KEY] = finalDict2
    # 合并字典
    merged_dict = {**outDict1, **outDict2}
    # 将合并后的字典导出成json字符串
    json_string = json.dumps(merged_dict)
    return json_string


CACHE_KEY_TO_GLOBAL_VAR = {
    REDIS_KEY_GITEE: 'redisKeyGitee',
    REDIS_KEY_FILE_NAME: 'file_name_dict',
    REDIS_KEY_GITHUB: 'redisKeyGithub',
    REDIS_KEY_WEBDAV: 'redisKeyWebDav',
    REDIS_KEY_SECRET_PASS_NOW: 'redisKeySecretPassNow',
    REDIS_KEY_FUNCTION_DICT: 'function_dict',
    REDIS_KEY_YOUTUBE: 'redisKeyYoutube',
    REDIS_KEY_BILIBILI: 'redisKeyBilili',
    REDIS_KEY_HUYA: 'redisKeyHuya',
    REDIS_KEY_YY: 'redisKeyYY'
}


def importToReloadCache(cachekey, dict):
    if cachekey in CACHE_KEY_TO_GLOBAL_VAR:
        global_var = globals()[CACHE_KEY_TO_GLOBAL_VAR[cachekey]]
        global_var.clear()
        global_var.update(dict)

    # Define mapping between cache keys and global variables


CACHE_KEY_TO_GLOBAL_VAR_SPECIAL = {
    REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME: 'downAndSecUploadUrlPassAndName',
    REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME: 'downAndDeSecUrlPassAndName'
}


def importToReloadCacheForSpecial(finalKey22, finalDict22):
    # Check cache key and update global variable accordingly
    if finalKey22 in CACHE_KEY_TO_GLOBAL_VAR_SPECIAL:
        global_var = globals()[CACHE_KEY_TO_GLOBAL_VAR_SPECIAL[finalKey22]]
        global_var.update(finalDict22)
        # Serialize global variable to JSON string and store in Redis
        json_string = json.dumps(global_var)
        r.set(finalKey22, json_string)


# 上传订阅配置
def upload_oneKey_json(request):
    try:
        json_dict = json.loads(request.get_data())
        # 批量写入数据
        pipe = r.pipeline()
        for key, value in json_dict.items():
            if key in NORMAL_REDIS_KEY:
                for finalKey11, finalDict11 in value.items():
                    if len(finalDict11) > 0:
                        pipe.hmset(finalKey11, finalDict11)
                        # redis_add_map(finalKey11, finalDict11)
                        importToReloadCache(finalKey11, finalDict11)
                        if len(finalDict11.keys()) > 100:
                            pipe.execute()
            elif key in SPECIAL_REDIS_KEY:
                for finalKey22, finalDict22 in value.items():
                    if len(finalDict22) > 0:
                        importToReloadCacheForSpecial(finalKey22, finalDict22)
        pipe.execute()
        return jsonify({'success': True})
    except Exception as e:
        print("An error occurred in upload_oneKey_json: ", e)
        return jsonify({'success': False})


def dellist(request, rediskey):
    # 获取 HTML 页面发送的 POST 请求参数
    deleteurl = request.json.get('deleteurl')
    r.hdel(rediskey, deleteurl)
    return jsonify({'deleteresult': "delete success"})


def download_json_file_base(redislinkKey):
    # 生成JSON文件数据
    json_data = generate_json_string(redislinkKey)
    filename = f'{secret_path}{redislinkKey}.json'
    if os.path.exists(filename):
        os.remove(filename)
    # 保存JSON数据到临时文件
    with open(filename, 'w') as f:
        f.write(json_data)
    # 发送JSON文件到前端
    return send_file(filename, as_attachment=True)


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
        redis_add_map(REDIS_KEY_PROXIES_TYPE, dict)
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


nameArr = ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'z', 'x', 'c',
           'v', 'b', 'n', 'm']


def download_files_for_encryp_proxy(urls, redis_dict):
    ip = init_IP()
    # 新生成的本地url
    proxy_dict = {}
    current_timestamp = int(time.time())
    i = 0
    round = 1
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # 提交下载任务并获取future对象列表
        future_to_url = {executor.submit(fetch_url, url, redis_dict): url for url in urls}
        # 获取各个future对象的返回值并存储在字典中
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
            except Exception as exc:
                print('%r generated an exception: %s' % (url, exc))
            else:
                index = 0
                middleStr = ""
                if i > 0 and i % 25 == 0:
                    round = round + 1
                while index < round:
                    middleStr += nameArr[i]
                    index = index + 1
                tmp_file = f"{current_timestamp}{middleStr}.yaml"
                with open(f"{secret_path}{tmp_file}", 'w'):
                    pass
                write_content_to_file(result.encode("utf-8"), f"{secret_path}{tmp_file}", 10)
                proxy_dict[f"http://{ip}:22771/secret/" + tmp_file] = f"{secret_path}{tmp_file}"
                i = i + 1
    return proxy_dict


def chaorongheProxies(filename):
    redis_dict = r.hgetall(REDIS_KEY_PROXIES_LINK)
    urlStr = ""
    urlAes = []
    for key in redis_dict.keys():
        url = key.decode('utf-8')
        if urlStr != "":
            urlStr += "|"
        # 提取加密的订阅
        password = redis_dict.get(key).decode()
        if password and password != "":
            urlAes.append(key)
        else:
            urlStr += url
    remoteToLocalUrl = download_files_for_encryp_proxy(urlAes, redis_dict)
    for key in remoteToLocalUrl.keys():
        if urlStr != "":
            urlStr += "|"
        urlStr += key
    params = generateProxyConfig(urlStr)
    # 本地配置   urllib.parse.quote("/path/to/clash/config_template.yaml"
    # 网络配置   "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini"
    try:
        response = requests.get(getProxyServerChosen(), params=params, timeout=360)
        if response.status_code == 200 and response.content != '':
            # 合并加密下载的和普通的
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
            thread = threading.Thread(target=download_secert_file,
                                      args=(
                                          filename, f"{public_path}{getFileNameByTagName('proxyConfigSecret')}.txt",
                                          'proxy', isOpenFunction('switch22'),
                                          isOpenFunction('switch23'), isOpenFunction('switch30'),
                                          isOpenFunction('switch31'), isOpenFunction('switch32')))
            thread.start()
            thread_remove(remoteToLocalUrl)
            return "result"
        else:
            try:
                # 使用转换器失败不能合并就直接把下载的一个订阅拿来用
                for key, filePath in remoteToLocalUrl.items():
                    os.rename(filePath, filename)
                    return "result"
                # 订阅失败处理逻辑
                print("Error:", response.status_code, response.reason)
                return "empty"
            except Exception as e:
                print("Error: fail to chaorongheProxy,instead,we download a remote yaml as the final proxy\n")
                pass
            finally:
                thread_remove(remoteToLocalUrl)
    except Exception as e:
        # 转换服务器找不到
        try:
            # 使用转换器失败不能合并就直接把下载的一个订阅拿来用
            for key, filePath in remoteToLocalUrl.items():
                if os.path.exists(filename):
                    os.remove(filename)
                os.rename(filePath, filename)
                return "result"
            # 订阅失败处理逻辑
            print("Error: fail to connect to proxy server")
            return "empty"
        except Exception as e:
            print("Error: fail to chaorongheProxy,instead,we download a remote yaml as the final proxy\n")
            pass
        finally:
            thread_remove(remoteToLocalUrl)


def thread_remove(remoteToLocalUrl):
    # url = ""
    for key in remoteToLocalUrl.values():
        try:
            if os.path.exists(key):
                os.remove(key)
        except Exception as e:
            pass


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


# 黑白名单线程数获取
def init_threads_num():
    data = threadsNum.get(REDIS_KEY_THREADS)
    if data and data > 0:
        return data
    num = redis_get(REDIS_KEY_THREADS)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 1000
            redis_add(REDIS_KEY_THREADS, num)
            threadsNum[REDIS_KEY_THREADS] = num
            redis_add(REDIS_KEY_UPDATE_THREAD_NUM_FLAG, 1)
        threadsNum[REDIS_KEY_THREADS] = num
    else:
        num = 1000
        redis_add(REDIS_KEY_THREADS, num)
        threadsNum[REDIS_KEY_THREADS] = num
        redis_add(REDIS_KEY_UPDATE_THREAD_NUM_FLAG, 1)
    return num


# dns并发查询数获取
def init_dns_timeout():
    data = dnstimeout.get(REDIS_KEY_DNS_TIMEOUT)
    if data and data > 0:
        return data
    num = redis_get(REDIS_KEY_DNS_TIMEOUT)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 20
            redis_add(REDIS_KEY_DNS_TIMEOUT, num)
            dnstimeout[REDIS_KEY_DNS_TIMEOUT] = num
        dnstimeout[REDIS_KEY_DNS_TIMEOUT] = num
    else:
        num = 20
        redis_add(REDIS_KEY_DNS_TIMEOUT, num)
        dnstimeout[REDIS_KEY_DNS_TIMEOUT] = num
    return num


# dns并发查询数获取
def init_dns_query_num():
    data = dnsquerynum.get(REDIS_KEY_DNS_QUERY_NUM)
    if data and data > 0:
        return data
    num = redis_get(REDIS_KEY_DNS_QUERY_NUM)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 150
            redis_add(REDIS_KEY_DNS_QUERY_NUM, num)
            dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = num
        dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = num
    else:
        num = 150
        redis_add(REDIS_KEY_DNS_QUERY_NUM, num)
        dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = num
    return num


# 中国DNS端口获取
def init_china_dns_port():
    data = chinadnsport.get(REDIS_KEY_CHINA_DNS_PORT)
    if data and data > 0:
        return data
    num = redis_get(REDIS_KEY_CHINA_DNS_PORT)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 5336
            redis_add(REDIS_KEY_CHINA_DNS_PORT, num)
            chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num
            redis_add(REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG, 1)
        chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num
    else:
        num = 5336
        redis_add(REDIS_KEY_CHINA_DNS_PORT, num)
        chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num
        redis_add(REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG, 1)
    return num


# 外国DNS端口获取
def init_extra_dns_port():
    data = extradnsport.get(REDIS_KEY_EXTRA_DNS_PORT)
    if data and data > 0:
        return data
    num = redis_get(REDIS_KEY_EXTRA_DNS_PORT)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 7874
            redis_add(REDIS_KEY_EXTRA_DNS_PORT, num)
            extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num
            redis_add(REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG, 1)
        extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num
    else:
        num = 7874
        redis_add(REDIS_KEY_EXTRA_DNS_PORT, num)
        extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num
        redis_add(REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG, 1)
    return num


# 中国DNS服务器获取
def init_china_dns_server():
    data = chinadnsserver.get(REDIS_KEY_CHINA_DNS_SERVER)
    if data and data != '':
        return data
    num = redis_get(REDIS_KEY_CHINA_DNS_SERVER)
    if num:
        num = num.decode()
        if num == "":
            num = "127.0.0.1"
            redis_add(REDIS_KEY_CHINA_DNS_SERVER, num)
            chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num
            redis_add(REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG, 1)
        chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num
    else:
        num = "127.0.0.1"
        redis_add(REDIS_KEY_CHINA_DNS_SERVER, num)
        chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num
        redis_add(REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG, 1)
    return num


# 外国DNS服务器获取
def init_extra_dns_server():
    data = extradnsserver.get(REDIS_KEY_EXTRA_DNS_SERVER)
    if data and data != '':
        return data
    num = redis_get(REDIS_KEY_EXTRA_DNS_SERVER)
    if num:
        num = num.decode()
        if num == "":
            num = "127.0.0.1"
            redis_add(REDIS_KEY_EXTRA_DNS_SERVER, num)
            extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num
            redis_add(REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG, 1)
        extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num
    else:
        num = "127.0.0.1"
        redis_add(REDIS_KEY_EXTRA_DNS_SERVER, num)
        extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num
        redis_add(REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG, 1)
    return num


def initReloadCacheForNormal():
    for redisKey in allListArr:
        if redisKey == REDIS_KEY_FUNCTION_DICT:
            init_function_dict()
        elif redisKey == REDIS_KEY_FILE_NAME:
            init_file_name()
    for redisKey in hugeDataList:
        if redisKey in REDIS_KEY_YOUTUBE:
            try:
                global redisKeyYoutube
                global redisKeyYoutubeM3u
                redisKeyYoutube.clear()
                dict = redis_get_map(REDIS_KEY_YOUTUBE)
                if dict:
                    redisKeyYoutube.update(dict)
                dict2 = redis_get_map(REDIS_KEY_YOUTUBE_M3U)
                if dict2:
                    redisKeyYoutubeM3u.update(dict2)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_BILIBILI:
            try:
                global redisKeyBilili
                global redisKeyBililiM3u
                redisKeyBilili.clear()
                dict = redis_get_map(REDIS_KEY_BILIBILI)
                if dict:
                    redisKeyBilili.update(dict)
                dict2 = redis_get_map(REDIS_KEY_BILIBILI_M3U)
                if dict2:
                    redisKeyBililiM3u.update(dict2)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_HUYA:
            try:
                global redisKeyHuya
                global redisKeyHuyaM3u
                redisKeyHuya.clear()
                dict = redis_get_map(REDIS_KEY_HUYA)
                if dict:
                    redisKeyHuya.update(dict)
                dict3 = redis_get_map(REDIS_KEY_HUYA_M3U)
                if dict3:
                    redisKeyHuyaM3u.update(dict3)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_YY:
            try:
                global redisKeyYY
                global redisKeyYYM3u
                redisKeyYY.clear()
                dict = redis_get_map(REDIS_KEY_YY)
                if dict:
                    redisKeyYY.update(dict)
                dict3 = redis_get_map(REDIS_KEY_YY_M3U)
                if dict3:
                    redisKeyYYM3u.update(dict3)
            except Exception as e:
                pass

def initReloadCacheForSpecial():
    for redisKey in specialRedisKey:
        if redisKey in REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME:
            try:
                # 从Redis中读取JSON字符串
                json_string_redis = r.get(redisKey)
                # 反序列化成Python对象
                my_dict_redis = json.loads(json_string_redis)
                global downAndSecUploadUrlPassAndName
                downAndSecUploadUrlPassAndName.clear()
                downAndSecUploadUrlPassAndName = my_dict_redis.copy()
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME:
            try:
                # 从Redis中读取JSON字符串
                json_string_redis = r.get(redisKey)
                # 反序列化成Python对象
                my_dict_redis = json.loads(json_string_redis)
                global downAndDeSecUrlPassAndName
                downAndDeSecUrlPassAndName.clear()
                downAndDeSecUrlPassAndName = my_dict_redis.copy()
            except Exception as e:
                pass


def init_pass(cacheKey):
    # redisKeySecretPassNow = {'m3u': '', 'whitelist': '', 'blacklist': '', 'ipv4': '', 'ipv6': '', 'proxy': ''}
    global redisKeySecretPassNow
    data = redisKeySecretPassNow.get(cacheKey)
    if data and data != '':
        return data
    dict = redis_get_map(REDIS_KEY_SECRET_PASS_NOW)
    if dict:
        value = dict.get(cacheKey)
        if value:
            redisKeySecretPassNow[cacheKey] = value
            return value
        else:
            value = generateEncryptPassword()
            redisKeySecretPassNow[cacheKey] = value
            tmp_dict = {}
            tmp_dict[cacheKey] = value
            redis_add_map(REDIS_KEY_SECRET_PASS_NOW, tmp_dict)
            return value
    else:
        value = generateEncryptPassword()
        redisKeySecretPassNow[cacheKey] = value
        tmp_dict = {}
        tmp_dict[cacheKey] = value
        redis_add_map(REDIS_KEY_SECRET_PASS_NOW, tmp_dict)
        return value


# 获取gitee数据
def init_gitee(cachekey, redisKey, cache):
    data = cache.get(cachekey)
    if data:
        return data
    allDict = redis_get_map(redisKey)
    if allDict:
        cacheValue = allDict.get(cachekey)
        if cacheValue:
            cacheValue = cacheValue
            cache[cachekey] = cacheValue
        else:
            cacheValue = ''
            cache[cachekey] = cacheValue
            tmp_dict = {cachekey: cacheValue}
            redis_add_map(redisKey, tmp_dict)
        return cacheValue
    else:
        cacheValue = ''
        cache[cachekey] = cacheValue
        tmp_dict = {cachekey: cacheValue}
        redis_add_map(redisKey, tmp_dict)
        return cacheValue


# gitee-修改数据
def update_gitee(cachekey, value, redisKey, cache):
    tmp_dict = {cachekey: value}
    # 设定默认选择的模板
    redis_add_map(redisKey, tmp_dict)
    cache[cachekey] = value


def changeFileName2(cachekey, newFileName):
    global file_name_dict
    tmp_dict = {}
    tmp_dict[cachekey] = newFileName
    redis_add_map(REDIS_KEY_FILE_NAME, tmp_dict)
    file_name_dict[cachekey] = newFileName
    return newFileName


# 直播源订阅密码刷新
def update_m3u_subscribe_pass_by_hand(cachekey, password):
    if cachekey == 'm3u':
        tagname = '直播源订阅'
    elif cachekey == 'proxy':
        tagname = '节点订阅'
    elif cachekey == 'ipv6':
        tagname = 'ipv6订阅'
    elif cachekey == 'ipv4':
        tagname = 'ipv4订阅'
    elif cachekey == 'blacklist':
        tagname = '域名黑名单订阅'
    elif cachekey == 'whitelist':
        tagname = '域名白名单订阅'
    # redisKeySecretPassNow = {'m3u': '', 'whitelist': '', 'blacklist': '', 'ipv4': '', 'ipv6': '', 'proxy': ''}
    global redisKeySecretPassNow
    oldpass = redisKeySecretPassNow.get(cachekey)
    if oldpass:
        addHistorySubscribePass(oldpass, tagname)
    else:
        oldpassDict = redis_get_map(REDIS_KEY_SECRET_PASS_NOW)
        if oldpassDict:
            oldpass = oldpassDict.get(cachekey)
            addHistorySubscribePass(oldpass.decode(), tagname)
    tmp_dict = {}
    tmp_dict[cachekey] = password
    redis_add_map(REDIS_KEY_SECRET_PASS_NOW, tmp_dict)
    redisKeySecretPassNow[cachekey] = password
    return password


# 直播源订阅密码刷新
def update_m3u_subscribe_pass(cachekey):
    tagname = ''
    if cachekey == 'm3u':
        tagname = '直播源订阅'
    elif cachekey == 'proxy':
        tagname = '节点订阅'
    elif cachekey == 'ipv6':
        tagname = 'ipv6订阅'
    elif cachekey == 'ipv4':
        tagname = 'ipv4订阅'
    elif cachekey == 'blacklist':
        tagname = '域名黑名单订阅'
    elif cachekey == 'whitelist':
        tagname = '域名白名单订阅'
    # redisKeySecretPassNow = {'m3u': '', 'whitelist': '', 'blacklist': '', 'ipv4': '', 'ipv6': '', 'proxy': ''}
    global redisKeySecretPassNow
    oldpass = redisKeySecretPassNow.get(cachekey)
    if oldpass:
        addHistorySubscribePass(oldpass, tagname)
    else:
        oldpassDict = redis_get_map(REDIS_KEY_SECRET_PASS_NOW)
        if oldpassDict:
            oldpass = oldpassDict.get(cachekey)
            addHistorySubscribePass(oldpass.decode(), tagname)
    password = generateEncryptPassword()
    tmp_dict = {}
    tmp_dict[cachekey] = password
    redis_add_map(REDIS_KEY_SECRET_PASS_NOW, tmp_dict)
    redisKeySecretPassNow[cachekey] = password
    return password


def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


# 生成订阅链接加密密码
def generateEncryptPassword():
    return generate_password() + "paperbluster" + base64.b64encode(os.urandom(16)).decode('utf-8')


# 返回字符串密码和比特流iv
def getIV(passwordStr):
    arr = passwordStr.split("paperbluster")
    iv_decoded = base64.b64decode(arr[1])
    return arr[0].encode('utf-8'), iv_decoded


# 加密函数   # bytes ciphertext
def encrypt(plaintext, cachekey):
    password = init_pass(cachekey)
    arr = getIV(password)
    # generate key and iv
    key = arr[0]
    # iv = os.urandom(16)
    # create cipher object
    backend = default_backend()
    algorithm = algorithms.AES(key)
    mode = modes.CTR(arr[1])
    cipher = Cipher(algorithm, mode, backend=backend)
    # encrypt plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # return ciphertext, iv, algorithm, and mode
    return ciphertext


# 加密函数   # bytes ciphertext
def encrypt2(plaintext, password):
    arr = getIV(password)
    # generate key and iv
    key = arr[0]
    # iv = os.urandom(16)
    # create cipher object
    backend = default_backend()
    algorithm = algorithms.AES(key)
    mode = modes.CTR(arr[1])
    cipher = Cipher(algorithm, mode, backend=backend)
    # encrypt plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # return ciphertext, iv, algorithm, and mode
    return ciphertext


# 解密函数 str-password,bytes secretcont
def decrypt(password, ciphertext):
    # generate key from password
    arr = getIV(password)
    key = arr[0]
    # create cipher object using the same algorithm, key and iv from encryption
    backend = default_backend()
    algorithm = algorithms.AES(key)
    mode = modes.CTR(arr[1])
    cipher = Cipher(algorithm, mode, backend=backend)
    # create a decryptor object
    decryptor = cipher.decryptor()
    fuck = decryptor.update(ciphertext)
    # decrypt ciphertext
    plaintext = fuck + decryptor.finalize()
    # return decrypted plaintext
    return plaintext


# 关键字，分组
m3u_whitlist = {}
# 分组,排名
m3u_whitlist_rank = {}
m3u_blacklist = {}


# 初始化m3u黑名单
def init_m3u_blacklist():
    global m3u_blacklist
    dict = redis_get_map(REDIS_KEY_M3U_BLACKLIST)
    if not dict or len(dict) == 0:
        dict = {'车载': '', "DJ音乐": '', '舞曲': ''}
        redis_add_map(REDIS_KEY_M3U_BLACKLIST, dict)
        m3u_blacklist = dict.copy()
    m3u_blacklist = dict.copy()


# 初始化m3u白名单
def init_m3u_whitelist():
    global m3u_whitlist
    global m3u_whitlist_rank
    dict = redis_get_map(REDIS_KEY_M3U_WHITELIST)
    dictRank = redis_get_map(REDIS_KEY_M3U_WHITELIST_RANK)
    if not dict or len(dict) == 0:
        dict = {"央視": "央视", "央视": "央视", "中央": "央视", "CCTV": "央视", "cctv": "央视",
                "衛視": "卫视", "卫视": "卫视", "CGTN": "央视", "環球電視": "央视", "环球电视": "央视",
                }
        redis_add_map(REDIS_KEY_M3U_WHITELIST, dict)
        m3u_whitlist = dict.copy()
    else:
        m3u_whitlist = dict.copy()
    if not dictRank or len(dictRank) == 0:
        dictRank = {'央视': '1', '卫视': '2'
                    }
        redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, dictRank)
        m3u_whitlist_rank = dictRank.copy()
    else:
        m3u_whitlist_rank = dictRank.copy()
    getRankWhiteList()


# 获取软路由主路由ip
def getMasterIp():
    # 获取宿主机IP地址
    host_ip = '192.168.5.1'
    return host_ip


# 外国DNS服务器获取
def init_IP():
    data = ip.get(REDIS_KEY_IP)
    if data and data != '':
        return data
    num = redis_get(REDIS_KEY_IP)
    if num:
        num = num.decode()
        if num == "":
            num = getMasterIp()
            redis_add(REDIS_KEY_IP, num)
            ip[REDIS_KEY_IP] = num
        ip[REDIS_KEY_IP] = num
    else:
        num = getMasterIp()
        redis_add(REDIS_KEY_IP, num)
        ip[REDIS_KEY_IP] = num
    return num


ignore_domain = ['com.', 'cn.', 'org.', 'net.', 'edu.', 'gov.', 'mil.', 'int.', 'biz.', 'info.', 'name.', 'pro.',
                 'asia.', 'us.', 'uk.', 'jp.']


# 大陆域名白名单放宽至一级域名
def stupidThinkForChina(domain_name):
    try:
        sub_domains = ['.'.join(domain_name.split('.')[i:]) for i in range(len(domain_name.split('.')) - 1)]
        domain = sub_domains[-1]
        for key in ignore_domain:
            if domain.startswith(key):
                try:
                    return sub_domains[-2]
                except Exception as e:
                    return ''
        return domain
    except Exception as e:
        return ''


# 提取二级、一级级域名
def stupidThink(domain_name):
    try:
        sub_domains = ['.'.join(domain_name.split('.')[i:]) for i in range(len(domain_name.split('.')) - 1)]
    except Exception as e:
        return ''
    try:
        return sub_domains[-2]
    except Exception as e:
        try:
            return sub_domains[-1]
        except Exception as e:
            return ''
    # sub_domains = []
    # for i in range(len(domain_name.split('.')) - 1):
    #     sub_domains.append('.'.join(domain_name.split('.')[i:]))
    # return sub_domains[len(sub_domains) - 1]


def addHistorySubscribePass(password, name):
    my_dict = {password: name}
    redis_add_map(REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS, my_dict)


file_name_dict_default = {'allM3u': 'allM3u', 'allM3uSecret': 'allM3uSecret', 'aliveM3u': 'aliveM3u',
                          'healthM3u': 'healthM3u',
                          'tvDomainForAdguardhome': 'tvDomainForAdguardhome',
                          'tvDomainForAdguardhomeSecret': 'tvDomainForAdguardhomeSecret',
                          'whiteListDnsmasq': 'whiteListDnsmasq', 'whiteListDnsmasqSecret': 'whiteListDnsmasqSecret',
                          'whiteListDomian': 'whiteListDomian',
                          'whiteListDomianSecret': 'whiteListDomianSecret',
                          'openclashFallbackFilterDomain': 'openclashFallbackFilterDomain',
                          'openclashFallbackFilterDomainSecret': 'openclashFallbackFilterDomainSecret',
                          'blackListDomain': 'blackListDomain',
                          'blackListDomainSecret': 'blackListDomainSecret', 'ipv4': 'ipv4', 'ipv4Secret': 'ipv4Secret',
                          'ipv6': 'ipv6',
                          'ipv6Secret': 'ipv6Secret', 'proxyConfig': 'proxyConfig',
                          'proxyConfigSecret': 'proxyConfigSecret',
                          'whitelistDirectRule': 'whitelistDirectRule', 'blacklistProxyRule': 'blacklistProxyRule',
                          'simpleOpenclashFallBackFilterDomain': 'simpleOpenclashFallBackFilterDomain',
                          'simpleblacklistProxyRule': 'simpleblacklistProxyRule', 'simpleDnsmasq': 'simpleDnsmasq',
                          'simplewhitelistProxyRule': 'simplewhitelistProxyRule', 'minTimeout': '5', 'maxTimeout': '30',
                          'maxTimeoutIgnoreLastUUID': '300', 'maxTimeoutIgnoreAllUUID': '3600',
                          'maxTimeoutTsSeen': '300', 'maxTimeoutTsFree': '300',
                          'maxTimeoutM3u8Free': '300', 'audioType': 'copy', 'ffmpegThread': '2', 'usernameSys': 'admin',
                          'passwordSys': 'password'}


def init_file_name():
    dict = redis_get_map(REDIS_KEY_FILE_NAME)
    if dict:
        global file_name_dict
        file_name_dict.clear()
        file_name_dict = dict.copy()
    else:
        redis_add_map(REDIS_KEY_FILE_NAME, file_name_dict_default)


def getFileNameByTagName(tagname):
    name = file_name_dict.get(tagname)
    if name and name != '':
        return name
    else:
        dict = redis_get_map(REDIS_KEY_FILE_NAME)
        if dict:
            name = dict.get(tagname)
            if name and name != '':
                file_name_dict[tagname] = name
                return name
            else:
                name = file_name_dict_default.get(tagname)
                file_name_dict[tagname] = name
                redis_add_map(REDIS_KEY_FILE_NAME, {tagname: name})
                return name
        else:
            name = file_name_dict_default.get(tagname)
            file_name_dict[tagname] = name
            redis_add_map(REDIS_KEY_FILE_NAME, {tagname: name})
            return name


############################################################协议区####################################################


# 获取节点订阅密码
@app.route('/api/getExtraDnsPort3', methods=['GET'])
@requires_auth
def getExtraDnsPort3():
    num = init_pass('proxy')
    return jsonify({'button': num})


# 获取IPV6订阅密码
@app.route('/api/getExtraDnsPort2', methods=['GET'])
@requires_auth
def getExtraDnsPort2():
    num = init_pass('ipv6')
    return jsonify({'button': num})


# 获取IPV4订阅密码
@app.route('/api/getExtraDnsServer2', methods=['GET'])
@requires_auth
def getExtraDnsServer2():
    num = init_pass('ipv4')
    return jsonify({'button': num})


# 获取域名黑名单订阅密码
@app.route('/api/getChinaDnsPort2', methods=['GET'])
@requires_auth
def getChinaDnsPort2():
    num = init_pass('blacklist')
    return jsonify({'button': num})


# 获取域名白名单订阅密码
@app.route('/api/getChinaDnsServer2', methods=['GET'])
@requires_auth
def getChinaDnsServer2():
    num = init_pass('whitelist')
    return jsonify({'button': num})


# 获取直播源订阅密码
@app.route('/api/getThreadNum2', methods=['GET'])
@requires_auth
def getThreadNum2():
    num = init_pass('m3u')
    return jsonify({'button': num})


# 删除加密订阅密码历史记录
@app.route('/api/deletewm3u14', methods=['POST'])
@requires_auth
def deletewm3u14():
    return dellist(request, REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS)


# 拉取全部加密订阅密码历史记录
@app.route('/api/getall14', methods=['GET'])
@requires_auth
def getall14():
    return jsonify(redis_get_map(REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS))


@app.route('/api/upload_json', methods=['POST'])
@requires_auth
def upload_json():
    # 从请求体中获取 rediskey 和文件内容
    data = request.get_json()
    rediskey = data.get('rediskey')
    file_content = data.get('content')
    if 'dnssimpleblacklist' == rediskey:
        redis_add(REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG, 1)
    elif 'dnssimplewhitelist' == rediskey:
        redis_add(REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG, 1)
    return upload_json_base(rediskey, file_content)


# 一键上传全部配置集合文件
@app.route('/api/upload_json_file7', methods=['POST'])
@requires_auth
def upload_json_file7():
    return upload_oneKey_json(request)


# 赞助-比特币
@app.route('/api/get_image')
def get_image():
    filename = '/app/img/bitcoin.png'
    return send_file(filename, mimetype='image/png')


# 查询功能开启状态
@app.route("/api/getSwitchstate", methods=['POST'])
@requires_auth
def getSwitchstate():
    id = request.json['id']
    global function_dict
    status = function_dict[id]
    return jsonify({"checkresult": status})


# 需要额外操作的
clockArr = ['switch25', 'switch26', 'switch27', 'switch28', 'switch13', 'switch25', 'switch33', 'switch34',
            'switch35']


# 切换功能开关
@app.route('/api/switchstate', methods=['POST'])
@requires_auth
def switchFunction():
    state = request.json['state']
    id = request.json['id']
    switchSingleFunction(id, state)
    return 'success'


def switchSingleFunction(id, state):
    if id in clockArr:
        toggle_m3u(id, state)
    else:
        global function_dict
        function_dict[id] = str(state)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)


# 批量切换功能开关
@app.route('/api/serverMode', methods=['POST'])
@requires_auth
def serverMode():
    mode = request.json['mode']
    if mode == 'server':
        switchSingleFunction('switch2', '1')
        switchSingleFunction('switch3', '1')
        switchSingleFunction('switch', '1')
        switchSingleFunction('switch4', '1')
        switchSingleFunction('switch5', '1')
        switchSingleFunction('switch6', '0')
        switchSingleFunction('switch7', '1')
        switchSingleFunction('switch8', '1')
        switchSingleFunction('switch9', '1')
        switchSingleFunction('switch10', '1')
        switchSingleFunction('switch11', '1')
        switchSingleFunction('switch12', '1')
        switchSingleFunction('switch13', '1')
        switchSingleFunction('switch14', '1')
        switchSingleFunction('switch15', '1')
        switchSingleFunction('switch16', '1')
        switchSingleFunction('switch17', '1')
        switchSingleFunction('switch18', '1')
        switchSingleFunction('switch19', '1')
        switchSingleFunction('switch20', '1')
        switchSingleFunction('switch21', '1')
        switchSingleFunction('switch22', '1')
        switchSingleFunction('switch23', '1')
        switchSingleFunction('switch24', '1')
        switchSingleFunction('switch25', '1')
        switchSingleFunction('switch26', '1')
        switchSingleFunction('switch27', '1')
        switchSingleFunction('switch28', '1')
        switchSingleFunction('switch30', '1')
        switchSingleFunction('switch31', '1')
        switchSingleFunction('switch32', '1')
        switchSingleFunction('switch33', '0')
        switchSingleFunction('switch34', '0')
        switchSingleFunction('switch35', '0')
    elif mode == 'client':
        switchSingleFunction('switch2', '0')
        switchSingleFunction('switch3', '0')
        switchSingleFunction('switch', '0')
        switchSingleFunction('switch4', '0')
        switchSingleFunction('switch5', '0')
        switchSingleFunction('switch6', '0')
        switchSingleFunction('switch7', '0')
        switchSingleFunction('switch8', '0')
        switchSingleFunction('switch9', '0')
        switchSingleFunction('switch10', '0')
        switchSingleFunction('switch11', '0')
        switchSingleFunction('switch12', '0')
        switchSingleFunction('switch13', '0')
        switchSingleFunction('switch14', '0')
        switchSingleFunction('switch15', '0')
        switchSingleFunction('switch16', '0')
        switchSingleFunction('switch17', '0')
        switchSingleFunction('switch18', '0')
        switchSingleFunction('switch19', '0')
        switchSingleFunction('switch20', '0')
        switchSingleFunction('switch21', '0')
        switchSingleFunction('switch22', '0')
        switchSingleFunction('switch23', '0')
        switchSingleFunction('switch24', '1')
        switchSingleFunction('switch25', '0')
        switchSingleFunction('switch26', '1')
        switchSingleFunction('switch27', '1')
        switchSingleFunction('switch28', '1')
        switchSingleFunction('switch30', '0')
        switchSingleFunction('switch31', '0')
        switchSingleFunction('switch32', '0')
        switchSingleFunction('switch33', '0')
        switchSingleFunction('switch34', '0')
        switchSingleFunction('switch35', '0')
    return 'success'


# 修改DNS并发查询数量
@app.route('/api/savetimeout', methods=['POST'])
@requires_auth
def savetimeout():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_DNS_TIMEOUT, int(data))
    dnstimeout[REDIS_KEY_DNS_TIMEOUT] = int(data)
    return "数据已经保存"


# DNS并发查询数
@app.route('/api/gettimeout', methods=['GET'])
@requires_auth
def gettimeout():
    num = init_dns_timeout()
    return jsonify({'button': num})


# 修改DNS并发查询数量
@app.route('/api/savequeryThreadNum', methods=['POST'])
@requires_auth
def savequeryThreadNum():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_DNS_QUERY_NUM, int(data))
    dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = int(data)
    return "数据已经保存"


# 获取DNS并发查询数量
@app.route('/api/getQueryThreadNum', methods=['GET'])
@requires_auth
def getQueryThreadNum():
    num = init_dns_query_num()
    return jsonify({'button': num})


# 删除DNS简易黑名单
@app.route('/api/deletewm3u13', methods=['POST'])
@requires_auth
def deletewm3u13():
    redis_add(REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG, 1)
    return dellist(request, REDIS_KEY_DNS_SIMPLE_BLACKLIST)


# 删除youtube直播源
@app.route('/api/deletewm3u24', methods=['POST'])
@requires_auth
def deletewm3u24():
    deleteurl = request.json.get('deleteurl')
    del redisKeyYoutube[deleteurl]
    return dellist(request, REDIS_KEY_YOUTUBE)


# 删除bilibili直播源
@app.route('/api/deletewm3u25', methods=['POST'])
@requires_auth
def deletewm3u25():
    deleteurl = request.json.get('deleteurl')
    del redisKeyBilili[deleteurl]
    return dellist(request, REDIS_KEY_BILIBILI)




# 删除huya直播源
@app.route('/api/deletewm3u26', methods=['POST'])
@requires_auth
def deletewm3u26():
    deleteurl = request.json.get('deleteurl')
    del redisKeyHuya[deleteurl]
    return dellist(request, REDIS_KEY_HUYA)


# 删除YY直播源
@app.route('/api/deletewm3u27', methods=['POST'])
@requires_auth
def deletewm3u27():
    deleteurl = request.json.get('deleteurl')
    del redisKeyYY[deleteurl]
    return dellist(request, REDIS_KEY_YY)


# 添加DNS简易黑名单
@app.route('/api/addnewm3u13', methods=['POST'])
@requires_auth
def addnewm3u13():
    redis_add(REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG, 1)
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    addurl = stupidThink(addurl)
    my_dict = {addurl: name}
    redis_add_map(REDIS_KEY_DNS_SIMPLE_BLACKLIST, my_dict)
    return jsonify({'addresult': "add success"})


# 拉取全部DNS简易黑名单
@app.route('/api/getall13', methods=['GET'])
@requires_auth
def getall13():
    return jsonify(redis_get_map(REDIS_KEY_DNS_SIMPLE_BLACKLIST))


# 拉取全部youtube
@app.route('/api/getall24', methods=['GET'])
@requires_auth
def getall24():
    global redisKeyYoutube
    return returnDictCache(REDIS_KEY_YOUTUBE, redisKeyYoutube)


# 拉取全部bilibili
@app.route('/api/getall25', methods=['GET'])
@requires_auth
def getall25():
    global redisKeyBilili
    return returnDictCache(REDIS_KEY_BILIBILI, redisKeyBilili)




# 拉取全部huya
@app.route('/api/getall26', methods=['GET'])
@requires_auth
def getall26():
    global redisKeyHuya
    return returnDictCache(REDIS_KEY_HUYA, redisKeyHuya)


# 拉取全部YY
@app.route('/api/getall27', methods=['GET'])
@requires_auth
def getall27():
    global redisKeyYY
    return returnDictCache(REDIS_KEY_YY, redisKeyYY)



def returnDictCache(redisKey, cacheDict):
    if len(cacheDict.keys()) > 0:
        return jsonify(cacheDict)
    dict = redis_get_map(redisKey)
    if dict:
        cacheDict.update(dict)
    return jsonify(cacheDict)


# 删除DNS简易白名单
@app.route('/api/deletewm3u12', methods=['POST'])
@requires_auth
def deletewm3u12():
    redis_add(REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG, 1)
    return dellist(request, REDIS_KEY_DNS_SIMPLE_WHITELIST)


# 添加DNS简易白名单
@app.route('/api/addnewm3u12', methods=['POST'])
@requires_auth
def addnewm3u12():
    redis_add(REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG, 1)
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    addurl = stupidThink(addurl)
    my_dict = {addurl: name}
    redis_add_map(REDIS_KEY_DNS_SIMPLE_WHITELIST, my_dict)
    return jsonify({'addresult': "add success"})


# 拉取全部DNS简易白名单
@app.route('/api/getall12', methods=['GET'])
@requires_auth
def getall12():
    return jsonify(redis_get_map(REDIS_KEY_DNS_SIMPLE_WHITELIST))


# 获取主机IP
@app.route('/api/getIP', methods=['GET'])
@requires_auth
def getIP():
    num = init_IP()
    return jsonify({'button': num})


# 修改主机IP
@app.route('/api/changeIP', methods=['POST'])
@requires_auth
def changeIP():
    data = request.json['selected_button']
    if data == "":
        data = getMasterIp()
    redis_add(REDIS_KEY_IP, data)
    ip[REDIS_KEY_IP] = data
    return "数据已经保存"


@app.route('/api/download_config', methods=['POST'])
@requires_auth
def handle_post_request():
    protocol = request.json.get('protocol')
    return download_json_file_base(protocol)


# 删除M3U白名单
@app.route('/api/deletewm3u11', methods=['POST'])
@requires_auth
def deletewm3u11():
    deleteurl = request.json.get('deleteurl')
    group = m3u_whitlist.get(deleteurl)
    del m3u_whitlist[deleteurl]
    checkAndRemoveM3uRank(group)
    return dellist(request, REDIS_KEY_M3U_WHITELIST)


# 删除M3U白名单分组优先级
@app.route('/api/deletewm3u16', methods=['POST'])
@requires_auth
def deletewm3u16():
    deleteurl = request.json.get('deleteurl')
    rank = m3u_whitlist_rank.get(deleteurl)
    del m3u_whitlist_rank[deleteurl]
    dealRemoveRankGroup(rank)
    return dellist(request, REDIS_KEY_M3U_WHITELIST_RANK)


def dealRemoveRankGroup(rank):
    rankNum = int(rank)
    updateDict = {}
    for key, value in m3u_whitlist_rank.items():
        num = int(value)
        if num <= rankNum:
            continue
        finalRank = str(num - 1)
        updateDict[key] = finalRank
        m3u_whitlist_rank[key] = finalRank
    if len(updateDict) > 0:
        redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, updateDict)
    getRankWhiteList()


def checkAndRemoveM3uRank(group):
    global m3u_whitlist_rank
    global m3u_whitlist
    if group not in m3u_whitlist.values():
        if group in m3u_whitlist_rank:
            rank = m3u_whitlist_rank.get(group)
            del m3u_whitlist_rank[group]
            r.hdel(REDIS_KEY_M3U_WHITELIST_RANK, group)
            rankNum = int(rank)
            updateDict = {}
            for key, value in m3u_whitlist_rank.items():
                num = int(value)
                if num <= rankNum:
                    continue
                finalRank = str(num - 1)
                updateDict[key] = finalRank
                m3u_whitlist_rank[key] = finalRank
            if len(updateDict) > 0:
                redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, updateDict)
    getRankWhiteList()


# 删除M3U黑名单
@app.route('/api/deletewm3u15', methods=['POST'])
@requires_auth
def deletewm3u15():
    deleteurl = request.json.get('deleteurl')
    del m3u_blacklist[deleteurl]
    return dellist(request, REDIS_KEY_M3U_BLACKLIST)


# 删除单个下载加密上传
@app.route('/api/deletewm3u17', methods=['POST'])
@requires_auth
def deletewm3u17():
    deleteurl = request.json.get('deleteurl')
    del downAndSecUploadUrlPassAndName[deleteurl]
    # 序列化成JSON字符串
    json_string = json.dumps(downAndSecUploadUrlPassAndName)
    # 将JSON字符串存储到Redis中
    r.set(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME, json_string)
    return jsonify({'deleteresult': "delete success"})


# 删除单个下载解密
@app.route('/api/deletewm3u18', methods=['POST'])
@requires_auth
def deletewm3u18():
    deleteurl = request.json.get('deleteurl')
    del downAndDeSecUrlPassAndName[deleteurl]
    # 序列化成JSON字符串
    json_string = json.dumps(downAndDeSecUrlPassAndName)
    # 将JSON字符串存储到Redis中
    r.set(REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME, json_string)
    return jsonify({'deleteresult': "delete success"})


# 添加M3U白名单
@app.route('/api/addnewm3u11', methods=['POST'])
@requires_auth
def addnewm3u11():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    checkAndUpdateM3uRank(name, -99)
    addurl_tw = convert(addurl, 'zh-tw')
    addurl_cn = convert(addurl, 'zh-cn')
    m3u_whitlist[addurl_tw] = name
    m3u_whitlist[addurl_cn] = name
    my_dict = {addurl_tw: name, addurl_cn: name}
    redis_add_map(REDIS_KEY_M3U_WHITELIST, my_dict)
    return jsonify({'addresult': "add success"})


# 添加youtube直播源
@app.route('/api/addnewm3u24', methods=['POST'])
@requires_auth
def addnewm3u24():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    redisKeyYoutube[addurl] = name
    return addlist(request, REDIS_KEY_YOUTUBE)


# 添加bilibili直播源
@app.route('/api/addnewm3u25', methods=['POST'])
@requires_auth
def addnewm3u25():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyBilili
    redisKeyBilili[addurl] = name
    return addlist(request, REDIS_KEY_BILIBILI)




# 添加huya直播源
@app.route('/api/addnewm3u26', methods=['POST'])
@requires_auth
def addnewm3u26():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyHuya
    redisKeyHuya[addurl] = name
    return addlist(request, REDIS_KEY_HUYA)


# 添加YY直播源
@app.route('/api/addnewm3u27', methods=['POST'])
@requires_auth
def addnewm3u27():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyYY
    redisKeyYY[addurl] = name
    return addlist(request, REDIS_KEY_YY)


# 添加M3U白名单分组优先级
@app.route('/api/addnewm3u16', methods=['POST'])
@requires_auth
def addnewm3u16():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    checkAndUpdateM3uRank(addurl, name)
    return jsonify({'addresult': "add success"})


# 添加下载加密上传-特殊字典结构保存到redis
@app.route('/api/addnewm3u17', methods=['POST'])
@requires_auth
def addnewm3u17():
    addurl = request.json.get('url')
    password = request.json.get('password')
    name = request.json.get('secretName')
    if len(downAndSecUploadUrlPassAndName.items()) == 0:
        # 从Redis中读取JSON字符串
        json_string_redis = r.get(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME)
        # 反序列化成Python对象
        my_dict_redis = json.loads(json_string_redis)
        downAndSecUploadUrlPassAndName.update(my_dict_redis)
    downAndSecUploadUrlPassAndName[addurl] = {'password': password, 'secretName': name}
    # 序列化成JSON字符串
    json_string = json.dumps(downAndSecUploadUrlPassAndName)
    # 将JSON字符串存储到Redis中
    r.set(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME, json_string)
    return jsonify({'addresult': "add success"})


# 添加下载解密-特殊字典结构保存到redis
@app.route('/api/addnewm3u18', methods=['POST'])
@requires_auth
def addnewm3u18():
    addurl = request.json.get('url')
    password = request.json.get('password')
    name = request.json.get('secretName')
    if len(downAndDeSecUrlPassAndName.items()) == 0:
        # 从Redis中读取JSON字符串
        json_string_redis = r.get(REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME)
        # 反序列化成Python对象
        my_dict_redis = json.loads(json_string_redis)
        downAndDeSecUrlPassAndName.update(my_dict_redis)
    downAndDeSecUrlPassAndName[addurl] = {'password': password, 'secretName': name}
    # 序列化成JSON字符串
    json_string = json.dumps(downAndDeSecUrlPassAndName)
    # 将JSON字符串存储到Redis中
    r.set(REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME, json_string)
    return jsonify({'addresult': "add success"})


def checkAndUpdateM3uRank(group, rank):
    if group == '':
        return
    global m3u_whitlist_rank
    global m3u_whitlist
    rankNum = int(rank)
    updateDict = {}
    updateDict[group] = rank
    # 新分组
    if group not in m3u_whitlist_rank:
        if rankNum == -99:
            maxnow = rankNum
            for key, value in m3u_whitlist_rank.items():
                num = int(value)
                maxnow = max(num, maxnow)
            maxnow = maxnow + 1
            updateDict[group] = str(maxnow)
            redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, updateDict)
            m3u_whitlist_rank[group] = str(maxnow)
        else:
            for key, value in m3u_whitlist_rank.items():
                num = int(value)
                if num < rankNum:
                    continue
                finalRank = str(num + 1)
                updateDict[key] = finalRank
                m3u_whitlist_rank[key] = finalRank
            redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, updateDict)
            m3u_whitlist_rank[group] = rank
    else:
        oldRank = int(m3u_whitlist_rank.get(group))
        # 排名后退，中间排名向前
        if oldRank < rankNum:
            for key, value in m3u_whitlist_rank.items():
                num = int(value)
                if num <= oldRank:
                    continue
                if num > rankNum:
                    continue
                finalRank = str(num - 1)
                updateDict[key] = finalRank
                m3u_whitlist_rank[key] = finalRank
        # 排名前进，中间排名向后
        elif oldRank > rankNum:
            for key, value in m3u_whitlist_rank.items():
                num = int(value)
                if num < rankNum:
                    continue
                if num >= oldRank:
                    continue
                finalRank = str(num + 1)
                updateDict[key] = finalRank
                m3u_whitlist_rank[key] = finalRank
        redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, updateDict)
        m3u_whitlist_rank[group] = rank
    getRankWhiteList()


# def getMaxRank():
#     global m3u_whitlist_rank
#     num = 0
#     for value in m3u_whitlist_rank.values():
#         num = max(num, int(value))
#     return str(num + 1)


# def checkAndUpdateM3uRank(group):
#     if group == '':
#         return
#     global m3u_whitlist_rank
#     global m3u_whitlist
#     # 新分组，默认加到最后
#     if group not in m3u_whitlist.values():
#         if group not in m3u_whitlist_rank:
#             rank = getMaxRank()
#             m3u_whitlist_rank[group] = rank
#             redis_add_map(REDIS_KEY_M3U_WHITELIST_RANK, {group, rank})
#     getRankWhiteList()


# 添加M3U黑名单
@app.route('/api/addnewm3u15', methods=['POST'])
@requires_auth
def addnewm3u15():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    m3u_blacklist[addurl] = name
    return addlist(request, REDIS_KEY_M3U_BLACKLIST)


# 拉取全部m3u白名单配置
@app.route('/api/getall11', methods=['GET'])
@requires_auth
def getall11():
    init_m3u_whitelist()
    return jsonify(m3u_whitlist)


# 拉取全部m3u白名单分组优先级配置
@app.route('/api/getall16', methods=['GET'])
@requires_auth
def getall16():
    init_m3u_whitelist()
    return jsonify(m3u_whitlist_rank)


# 拉取全部下载加密上传
@app.route('/api/getall17', methods=['GET'])
@requires_auth
def getall17():
    return jsonify(downAndSecUploadUrlPassAndName)


# 拉取全部下载解密
@app.route('/api/getall18', methods=['GET'])
@requires_auth
def getall18():
    return jsonify(downAndDeSecUrlPassAndName)


# 拉取全部m3u黑名单配置
@app.route('/api/getall15', methods=['GET'])
@requires_auth
def getall15():
    init_m3u_blacklist()
    return jsonify(m3u_blacklist)


# 通用获取同步账户数据-cachekey,flag(bbs-gitee,pps-github,lls-webdav)
@app.route('/api/getSyncAccountData', methods=['POST'])
@requires_auth
def getSyncAccountData():
    cacheKey = request.json['cacheKey']
    type = request.json['inputvalue']
    if type == 'bbs':
        global redisKeyGitee
        num = init_gitee(cacheKey, REDIS_KEY_GITEE, redisKeyGitee)
        return jsonify({'password': num})
    elif type == 'pps':
        global redisKeyGithub
        num = init_gitee(cacheKey, REDIS_KEY_GITHUB, redisKeyGithub)
        return jsonify({'password': num})
    elif type == 'lls':
        global redisKeyWebDav
        num = init_gitee(cacheKey, REDIS_KEY_WEBDAV, redisKeyWebDav)
        return jsonify({'password': num})


# 修改同步账户数据    gitee-bbs github-pps webdav-lls
@app.route('/api/changeSyncData', methods=['POST'])
@requires_auth
def changeSyncData():
    cacheKey = request.json['cacheKey']
    type = request.json['type']
    value = request.json['inputvalue']
    if type == 'bbs':
        global redisKeyGitee
        update_gitee(cacheKey, value, REDIS_KEY_GITEE, redisKeyGitee)
    elif type == 'pps':
        global redisKeyGithub
        update_gitee(cacheKey, value, REDIS_KEY_GITHUB, redisKeyGithub)
    elif type == 'lls':
        global redisKeyWebDav
        update_gitee(cacheKey, value, REDIS_KEY_WEBDAV, redisKeyWebDav)
    return "数据已经保存"


# 通用随机订阅密码切换
@app.route("/api/changeSubscribePassword", methods=['POST'])
@requires_auth
def changeSubscribePassword():
    cacheKey = request.json['cacheKey']
    num = update_m3u_subscribe_pass(cacheKey)
    return jsonify({"password": num})


# 通用随机订阅密码切换-下载加密上传功能
@app.route("/api/changeSubscribePassword2", methods=['POST'])
@requires_auth
def changeSubscribePassword2():
    url = request.json['cacheKey']
    password = generateEncryptPassword()
    global downAndSecUploadUrlPassAndName
    myDict = downAndSecUploadUrlPassAndName.get(url)
    if myDict:
        myDict['password'] = password
        # 序列化成JSON字符串
        json_string = json.dumps(downAndSecUploadUrlPassAndName)
        # 将JSON字符串存储到Redis中
        r.set(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME, json_string)
    return jsonify({"password": password})


# 查询订阅文件名字
@app.route("/api/getFileName", methods=['POST'])
@requires_auth
def getFileName():
    cacheKey = request.json['cacheKey']
    num = getFileNameByTagName(cacheKey)
    return jsonify({"password": num})


# 通用订阅文件名字手动修改
@app.route("/api/changeFileName", methods=['POST'])
@requires_auth
def changeFileName():
    cacheKey = request.json['cacheKey']
    newName = request.json['inputvalue']
    num = changeFileName2(cacheKey, newName)
    return jsonify({"password": num})


# 通用订阅密码手动修改
@app.route("/api/changeSubscribePasswordByHand", methods=['POST'])
@requires_auth
def changeSubscribePasswordByHand():
    cacheKey = request.json['cacheKey']
    password = request.json['inputvalue']
    num = update_m3u_subscribe_pass_by_hand(cacheKey, password)
    return jsonify({"password": num})


# 获取外国DNS端口
@app.route('/api/getExtraDnsPort', methods=['GET'])
@requires_auth
def getExtraDnsPort():
    num = init_extra_dns_port()
    return jsonify({'button': num})


# 修改外国DNS端口
@app.route('/api/saveExtraDnsPort', methods=['POST'])
@requires_auth
def saveExtraDnsPort():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_EXTRA_DNS_PORT, int(data))
    extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = int(data)
    redis_add(REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG, 1)
    return "数据已经保存"


# 获取外国DNS服务器
@app.route('/api/getExtraDnsServer', methods=['GET'])
@requires_auth
def getExtraDnsServer():
    num = init_extra_dns_server()
    return jsonify({'button': num})


# 修改外国DNS服务器
@app.route('/api/saveExtraDnsServer', methods=['POST'])
@requires_auth
def saveExtraDnsServer():
    data = request.json['selected_button']
    if data == "":
        data = "127.0.0.1"
    redis_add(REDIS_KEY_EXTRA_DNS_SERVER, data)
    extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = data
    redis_add(REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG, 1)
    return "数据已经保存"


# 获取中国DNS端口
@app.route('/api/getChinaDnsPort', methods=['GET'])
@requires_auth
def getChinaDnsPort():
    num = init_china_dns_port()
    return jsonify({'button': num})


# 修改中国DNS端口
@app.route('/api/savechinaDnsPort', methods=['POST'])
@requires_auth
def savechinaDnsPort():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_CHINA_DNS_PORT, int(data))
    chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = int(data)
    redis_add(REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG, 1)
    return "数据已经保存"


# 获取中国DNS服务器
@app.route('/api/getChinaDnsServer', methods=['GET'])
@requires_auth
def getChinaDnsServer():
    num = init_china_dns_server()
    return jsonify({'button': num})


# 修改中国DNS服务器
@app.route('/api/savechinaDnsServer', methods=['POST'])
@requires_auth
def savechinaDnsServer():
    data = request.json['selected_button']
    if data == "":
        data = "127.0.0.1"
    redis_add(REDIS_KEY_CHINA_DNS_SERVER, data)
    chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = data
    redis_add(REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG, 1)
    return "数据已经保存"


# 获取黑白名单并发检测线程数
@app.route('/api/getThreadNum', methods=['GET'])
@requires_auth
def getThreadNum():
    num = init_threads_num()
    return jsonify({'button': num})


# 修改黑白名单并发检测线程数
@app.route('/api/saveThreadS', methods=['POST'])
@requires_auth
def saveThreadS():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_THREADS, min(int(data), 1000))
    threadsNum[REDIS_KEY_THREADS] = min(int(data), 1000)
    redis_add(REDIS_KEY_UPDATE_THREAD_NUM_FLAG, 1)
    return "数据已经保存"


# 选择目标转换的远程配置
@app.route('/api/chooseProxyModel', methods=['POST'])
@requires_auth
def chooseProxyModel():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_MODEL_CHOSEN] = button
    redis_add_map(REDIS_KEY_PROXIES_MODEL_CHOSEN, dict)
    return "success"


# 选择目标转换的远程服务器
@app.route('/api/chooseProxyServer', methods=['POST'])
@requires_auth
def chooseProxyServer():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = button
    redis_add_map(REDIS_KEY_PROXIES_SERVER_CHOSEN, dict)
    return "success"


# 服务器启动时加载选择的配置
@app.route('/api/getSelectedModel', methods=['GET'])
@requires_auth
def getSelectedModel():
    dict = redis_get_map(REDIS_KEY_PROXIES_MODEL_CHOSEN)
    if dict:
        value = dict[REDIS_KEY_PROXIES_MODEL_CHOSEN]
        if value:
            return jsonify({'button': value})
        else:
            tmp_dict = {}
            tmp_dict[REDIS_KEY_PROXIES_MODEL_CHOSEN] = "ACL4SSR_Online 默认版 分组比较全(本地离线模板)"
            # 设定默认选择的模板
            redis_add_map(REDIS_KEY_PROXIES_MODEL_CHOSEN, tmp_dict)
            return jsonify({'button': tmp_dict[REDIS_KEY_PROXIES_MODEL_CHOSEN]})
    else:
        tmp_dict = {}
        tmp_dict[REDIS_KEY_PROXIES_MODEL_CHOSEN] = "ACL4SSR_Online 默认版 分组比较全(本地离线模板)"
        # 设定默认选择的模板
        redis_add_map(REDIS_KEY_PROXIES_MODEL_CHOSEN, tmp_dict)
        return jsonify({'button': tmp_dict[REDIS_KEY_PROXIES_MODEL_CHOSEN]})


# 服务器启动时加载选择的服务器
@app.route('/api/getSelectedServer', methods=['GET'])
@requires_auth
def getSelectedServer():
    dict = redis_get_map(REDIS_KEY_PROXIES_SERVER_CHOSEN)
    if dict:
        value = dict[REDIS_KEY_PROXIES_SERVER_CHOSEN]
        if value:
            return jsonify({'button': value})
        else:
            tmp_dict = {}
            tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = "bridge模式:本地服务器"
            redis_add_map(REDIS_KEY_PROXIES_SERVER_CHOSEN, tmp_dict)
            return jsonify({'button': tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN]})
    else:
        tmp_dict = {}
        tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = "bridge模式:本地服务器"
        redis_add_map(REDIS_KEY_PROXIES_SERVER_CHOSEN, tmp_dict)
        return jsonify({'button': tmp_dict[REDIS_KEY_PROXIES_SERVER_CHOSEN]})


# 拉取列表-代理模板
@app.route('/api/reloadProxyModels', methods=['GET'])
@requires_auth
def reloadProxyModels():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_SERVER))


# 删除节点远程后端服务器订阅
@app.route('/api/deletewm3u10', methods=['POST'])
@requires_auth
def deletewm3u10():
    returnJson = dellist(request, REDIS_KEY_PROXIES_SERVER)
    setRandomValueChosen(REDIS_KEY_PROXIES_SERVER, REDIS_KEY_PROXIES_SERVER_CHOSEN)
    return returnJson


# 添加节点后端订阅
@app.route('/api/addnewm3u10', methods=['POST'])
@requires_auth
def addnewm3u10():
    return addlist(request, REDIS_KEY_PROXIES_SERVER)


# 拉取全部后端服务器配置
@app.route('/api/getall10', methods=['GET'])
@requires_auth
def getall10():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_SERVER))


# 删除节点远程配置订阅
@app.route('/api/deletewm3u9', methods=['POST'])
@requires_auth
def deletewm3u9():
    returnJson = dellist(request, REDIS_KEY_PROXIES_MODEL)
    setRandomValueChosen(REDIS_KEY_PROXIES_MODEL, REDIS_KEY_PROXIES_MODEL_CHOSEN)
    return returnJson


# 添加节点远程配置订阅
@app.route('/api/addnewm3u9', methods=['POST'])
@requires_auth
def addnewm3u9():
    return addlist(request, REDIS_KEY_PROXIES_MODEL)


# 拉取全部节点订阅远程配置
@app.route('/api/getall9', methods=['GET'])
@requires_auth
def getall9():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_MODEL))


# 服务器启动时加载选择的节点类型id
@app.route('/api/getSelectedButtonId', methods=['GET'])
@requires_auth
def getSelectedButtonId():
    button = getProxyButton()
    return jsonify({'button': button})


# 选择目标转换的节点类型id
@app.route('/api/chooseProxy', methods=['POST'])
@requires_auth
def chooseProxy():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_TYPE] = button
    redis_add_map(REDIS_KEY_PROXIES_TYPE, dict)
    return "success"


# 删除节点订阅
@app.route('/api/deletewm3u8', methods=['POST'])
@requires_auth
def deletewm3u8():
    return dellist(request, REDIS_KEY_PROXIES_LINK)


# 添加节点订阅
@app.route('/api/addnewm3u8', methods=['POST'])
@requires_auth
def addnewm3u8():
    return addlist(request, REDIS_KEY_PROXIES_LINK)


# 拉取全部节点订阅
@app.route('/api/getall8', methods=['GET'])
@requires_auth
def getall8():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_LINK))


# 全部节点订阅链接超融合
@app.route('/api/chaoronghe6', methods=['GET'])
@requires_auth
def chaoronghe_proxy():
    return chaoronghe6()


def chaoronghe6():
    try:
        return chaorongheProxies(f"{secret_path}{getFileNameByTagName('proxyConfig')}.yaml")
    except:
        return "empty"


# 简易DNS黑名单超融合：op黑名单代理域名+代理规则
@app.route('/api/chaoronghe7', methods=['GET'])
@requires_auth
def chaoronghe_simpleBlacklist():
    return chaoronghe7()


def chaoronghe7():
    path1 = f"{secret_path}{getFileNameByTagName('simpleOpenclashFallBackFilterDomain')}.txt"
    path2 = f"{secret_path}{getFileNameByTagName('simpleblacklistProxyRule')}.txt"
    try:
        return chaoronghebase2(REDIS_KEY_DNS_SIMPLE_BLACKLIST,
                               path1,
                               OPENCLASH_FALLBACK_FILTER_DOMAIN_LEFT,
                               OPENCLASH_FALLBACK_FILTER_DOMAIN_RIGHT,
                               path2,
                               PROXY_RULE_LEFT)
    except Exception as e:
        return "empty"


# 简易DNS白名单超融合:白名单dnsmasq配置+白名单代理规则
@app.route('/api/chaoronghe8', methods=['GET'])
@requires_auth
def chaoronghe_simpleWhitelist():
    return chaoronghe8()


def chaoronghe8():
    path1 = f"{secret_path}{getFileNameByTagName('simpleDnsmasq')}.conf"
    path2 = f"{secret_path}{getFileNameByTagName('simplewhitelistProxyRule')}.txt"
    try:
        return chaoronghebase2(REDIS_KEY_DNS_SIMPLE_WHITELIST, path1
                               ,
                               BLACKLIST_DNSMASQ_FORMATION_LEFT,
                               BLACKLIST_DNSMASQ_FORMATION_right,
                               path2,
                               DIRECT_RULE_LEFT)
    except Exception as e:
        return "empty"


def getUrlFileName(url):
    arr = url.split('/')
    return arr[len(arr) - 1]


# 下载加密上传执行
@app.route('/api/chaoronghe9', methods=['GET'])
@requires_auth
def chaoronghe_downAndUpload():
    return chaoronghe9()


def chaoronghe9():
    global downAndSecUploadUrlPassAndName
    urls = []
    passwordDict = {}
    filenameDict = {}
    secretNameDict = {}
    try:
        for url, urlDict in downAndSecUploadUrlPassAndName.items():
            password = urlDict['password']
            secretName = urlDict['secretName']
            filename = getUrlFileName(url)
            filenameDict[url] = f"{secret_path}{filename}"
            secretNameDict[url] = f"{public_path}{secretName}"
            urls.append(url)
            passwordDict[url] = password
        download_files2(urls, passwordDict, filenameDict, secretNameDict,
                        isOpenFunction('switch30'),
                        isOpenFunction('switch31'), isOpenFunction('switch32'))
        return "result"
    except Exception as e:
        return "empty"


# 下载解密
@app.route('/api/chaoronghe10', methods=['GET'])
@requires_auth
def chaoronghe_downAndDesecret():
    return chaoronghe10()


def chaoronghe10():
    global downAndDeSecUrlPassAndName
    urls = []
    passwordDict = {}
    filenameDict = {}
    try:
        for url, urlDict in downAndDeSecUrlPassAndName.items():
            password = urlDict['password']
            secretName = urlDict['secretName']
            filenameDict[url] = f"{secret_path}{secretName}"
            urls.append(url)
            passwordDict[url] = password
        download_files3(urls, passwordDict, filenameDict)
        return "result"
    except Exception as e:
        return "empty"


async def download_file5_single(ids, mintimeout, maxTimeout):
    m3u_dict = {}
    try:
        sem = asyncio.Semaphore(1000)  # 限制TCP连接的数量为100个
        async with aiohttp.ClientSession() as session:
            tasks = []
            for id in ids:
                task = asyncio.ensure_future(grab2(session, id, m3u_dict, sem, mintimeout, maxTimeout))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"bilibili Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files5():
    global redisKeyBilili
    ids = redisKeyBilili.keys()
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    m3u_dict = await download_file5_single(ids, mintimeout, maxTimeout)
    return m3u_dict

async def download_files6_single(ids, mintimeout, maxTimeout):
    m3u_dict = {}
    try:
        sem = asyncio.Semaphore(1000)  # 限制TCP连接的数量为100个
        async with aiohttp.ClientSession() as session:
            tasks = []
            for id in ids:
                task = asyncio.ensure_future(grab3(session, id, m3u_dict, sem, mintimeout, maxTimeout))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files6():
    global redisKeyHuya
    ids = redisKeyHuya.keys()
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    m3u_dict = await download_files6_single(ids, mintimeout, maxTimeout)
    return m3u_dict


async def download_files7_single(ids, mintimeout, maxTimeout):
    m3u_dict = {}
    try:
        sem = asyncio.Semaphore(1000)  # 限制TCP连接的数量为100个
        async with aiohttp.ClientSession() as session:
            tasks = []
            for id in ids:
                task = asyncio.ensure_future(grab4(session, id, m3u_dict, sem, mintimeout, maxTimeout))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files7():
    global redisKeyYY
    ids = redisKeyYY.keys()
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    m3u_dict = await download_files7_single(ids, mintimeout, maxTimeout)
    return m3u_dict


# 先获取直播状态和真实房间号
bilibili_real_url = 'https://api.live.bilibili.com/room/v1/Room/room_init'
bili_header = {
    'User-Agent': 'Mozilla/5.0 (iPod; CPU iPhone OS 14_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, '
                  'like Gecko) CriOS/87.0.4280.163 Mobile/15E148 Safari/604.1',
}

# 转换为 CIMultiDict 对象
cim_headers = CIMultiDict(bili_header)

biliurl = 'https://api.live.bilibili.com/xlive/web-room/v2/index/getRoomPlayInfo'


async def grab2(session, id, m3u_dict, sem, mintimeout, maxTimeout):
    try:
        param = {
            'id': id
        }
        try:
            async with sem, session.get(bilibili_real_url, headers=cim_headers, params=param,
                                        timeout=mintimeout) as response:
                res = await response.json()
        except asyncio.TimeoutError:
            async with sem, session.get(bilibili_real_url, headers=cim_headers, params=param,
                                        timeout=maxTimeout) as response:
                res = await response.json()
        if '不存在' in res['msg']:
            return
        live_status = res['data']['live_status']
        if live_status != 1:
            return
        real_room_id = res['data']['room_id']
        param2 = {
            'room_id': real_room_id,
            'protocol': '0,1',
            'format': '0,1,2',
            'codec': '0,1',
            'qn': 10000,
            'platform': 'web',
            'ptype': 8,
        }
        try:
            async with sem, session.get(biliurl, headers=cim_headers, params=param2, timeout=mintimeout) as response2:
                res = await response2.json()
        except asyncio.TimeoutError:
            async with sem, session.get(biliurl, headers=cim_headers, params=param2, timeout=maxTimeout) as response2:
                res = await response2.json()
        stream_info = res['data']['playurl_info']['playurl']['stream']
        accept_qn = stream_info[0]['format'][0]['codec'][0]['accept_qn']
        real_lists = []
        real_dict = {}
        nameArr = []
        for data in stream_info:
            format_name = data['format'][0]['format_name']
            if format_name == 'ts':
                base_url = data['format'][-1]['codec'][0]['base_url']
                url_info = data['format'][-1]['codec'][0]['url_info']
                for i, info in enumerate(url_info):
                    for qn in accept_qn:
                        url_ = base_url
                        host = info['host']
                        extra = info['extra']
                        if qn < 10000:
                            qn = qn * 10
                            url_ = re.sub('bluray/index', f'{qn}/index', base_url)
                        elif qn > 10000:
                            continue
                        extra = re.sub('qn=(\d+)', f'qn={qn}', extra)
                        if qn == 10000:
                            namestr = f'线路{i + 1}_{qn}'
                            nameArr.append(namestr)
                            real_lists.append({namestr: f'{host}{url_}{extra}'})
                break
        if real_lists:
            tasks = []
            for real_ in real_lists:
                for key, value in real_.items():
                    task = asyncio.ensure_future(pingM3u(session, value, real_dict, key, sem, mintimeout, maxTimeout))
                    tasks.append(task)
            await asyncio.gather(*tasks)
            if real_dict:
                isOne = len(nameArr) == 1
                if isOne:
                    for key, value in real_dict.items():
                        if nameArr[0] == key:
                            m3u_dict[id] = value
                            return
                else:
                    for i in range(len(nameArr) - 1):
                        for key, value in real_dict.items():
                            if nameArr[i] == key:
                                m3u_dict[id] = value
                                return
                return
        return
    except Exception as e:
        print(f"bilibili An error occurred while processing {id}. Error: {e}")

def huya_live(e):
    i, b = e.split('?')
    r = i.split('/')
    s = re.sub(r'.(flv|m3u8)', '', r[-1])
    c = b.split('&', 3)
    c = [i for i in c if i != '']
    n = {i.split('=')[0]: i.split('=')[1] for i in c}
    fm = urllib.parse.unquote(n['fm'])
    u = base64.b64decode(fm).decode('utf-8')
    p = u.split('_')[0]
    f = str(int(time.time() * 1e7))
    l = n['wsTime']
    t = '0'
    h = '_'.join([p, t, s, f, l])
    m = hashlib.md5(h.encode('utf-8')).hexdigest()
    y = c[-1]
    url = "{}?wsSecret={}&wsTime={}&u={}&seqid={}&{}".format(i, m, l, t, f, y)
    return url


huya_header = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/75.0.3770.100 Mobile Safari/537.36 '
}
# 转换为 CIMultiDict 对象
cim_headers_huya = CIMultiDict(huya_header)

headers_web_YY = {
    'referer': f'https://www.yy.com/',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36 '
}

headers_YY = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/95.0.4638.69 Safari/537.36 '
}


async def room_id_(session, id, sem, mintimeout, maxTimeout):
    url = 'https://www.yy.com/{}'.format(id)
    try:
        async with sem, session.get(url, headers=headers_web_YY, timeout=mintimeout) as response:
            if response.status == 200:
                room_id = re.findall('ssid : "(\d+)', response.text)[0]
                return room_id
    except asyncio.TimeoutError:
        async with sem, session.get(url, headers=headers_web_YY, timeout=maxTimeout) as response:
            if response.status == 200:
                room_id = re.findall('ssid : "(\d+)', response.text)[0]
                return room_id


async def fetch_room_url(session, room_url, headers, sem, mintimeout, maxTimeout):
    try:
        async with sem, session.get(room_url, headers=headers, timeout=mintimeout) as response:
            if response.status == 200:
                return await response.text()
            else:
                return None
    except asyncio.TimeoutError:
        async with sem, session.get(room_url, headers=headers, timeout=maxTimeout) as response:
            if response.status == 200:
                return await response.text()
            else:
                return None


async def fetch_real_url(session, url, headers, sem, mintimeout, maxTimeout):
    try:
        async with sem, session.get(url, headers=headers, timeout=mintimeout) as response:
            if response.status == 200:
                return await response.text()
            else:
                return None
    except asyncio.TimeoutError:
        async with sem, session.get(url, headers=headers, timeout=maxTimeout) as response:
            if response.status == 200:
                return await response.text()
            else:
                return None


cim_headers_YY = CIMultiDict(headers_YY)


async def grab4(session, id, m3u_dict, sem, mintimeout, maxTimeout):
    try:
        headers_YY['referer'] = f'https://wap.yy.com/mobileweb/{id}'
        real_lists = []
        real_dict = {}
        arr = []
        room_url = f'https://interface.yy.com/hls/new/get/{id}/{id}/1200?source=wapyy&callback='
        res_text = await fetch_room_url(session, room_url, headers_YY, sem, mintimeout, maxTimeout)
        if not res_text:
            try:
                room_id = await room_id_(session, id, sem, mintimeout, maxTimeout)
            except Exception as e:
                return
            room_url = f'https://interface.yy.com/hls/new/get/{room_id}/{room_id}/1200?source=wapyy&callback='
            res_text = await fetch_room_url(session, room_url, headers_YY, sem, mintimeout, maxTimeout)
        if res_text:
            data = json.loads(res_text[1:-1])
            if data.get('hls', 0):
                xa = data['audio']
                xv = data['video']
                xv = re.sub(r'_0_\d+_0', '_0_0_0', xv)
                url = f'https://interface.yy.com/hls/get/stream/15013/{xv}/15013/{xa}?source=h5player&type=m3u8'
                res_json = await  fetch_real_url(session, url, cim_headers_YY, sem, mintimeout, maxTimeout)
                if not res_json:
                    return
                res_json = json.loads(res_json)
                # 取画质最高的
                if res_json and res_json.get('hls', 0):
                    real_url = res_json['hls']
                    real_lists.append({'hls': real_url})
                    arr.append(f'hls')
            if real_lists:
                tasks = []
                for real_ in real_lists:
                    for key, value in real_.items():
                        task = asyncio.ensure_future(
                            pingM3u(session, value, real_dict, key, sem, mintimeout, maxTimeout))
                        tasks.append(task)
                await asyncio.gather(*tasks)
                if real_dict:
                    isOne = len(arr) == 1
                    if isOne:
                        for key, value in real_dict.items():
                            if arr[0] == key:
                                # 有效直播源,名字/id
                                m3u_dict[id] = value
                                return
                    else:
                        for i in range(len(arr) - 1):
                            for key, value in real_dict.items():
                                if arr[i] == key:
                                    m3u_dict[id] = value
                                    return
                    return
            return
    except Exception as e:
        print(f"YY An error occurred while processing {id}. Error: {e}")


async def grab3(session, id, m3u_dict, sem, mintimeout, maxTimeout):
    try:
        param = {
            'id': id
        }
        real_lists = []
        real_dict = {}
        arr = []
        huya_room_url = 'https://m.huya.com/{}'.format(id)
        try:
            async with sem, session.get(huya_room_url, headers=cim_headers_huya, params=param,
                                        timeout=mintimeout) as response:
                res = await response.text()
        except asyncio.TimeoutError:
            async with sem, session.get(huya_room_url, headers=cim_headers_huya, params=param,
                                        timeout=maxTimeout) as response:
                res = await response.text()
        liveLineUrl = re.findall(r'"liveLineUrl":"([\s\S]*?)",', res)[0]
        liveline = base64.b64decode(liveLineUrl).decode('utf-8')
        if liveline:
            if 'replay' in liveline:
                real_lists.append({'直播录像': f'https://{liveline}'})
            else:
                liveline = huya_live(liveline)
                real_url = ("https:" + liveline).replace("hls", "flv").replace("m3u8", "flv").replace(
                    '&ctype=tars_mobile', '')
                rate = [10000, 8000, 4000]
                # rate = [10000, 8000, 4000, 2000, 500]
                arr.append(f'flv_10000')
                arr.append(f'flv_8000')
                arr.append(f'flv_4000')
                # arr.append(f'flv_2000')
                # arr.append(f'flv_500')
                for ratio in range(len(rate) - 1, -1, -1):
                    ratio = rate[ratio]
                    if ratio != 10000:
                        real_url_flv = real_url.replace('.flv?', f'.flv?ratio={ratio}&')
                        name = f'flv_{ratio}'
                        real_lists.append({name: real_url_flv})
                    else:
                        name = f'flv_{ratio}'
                        real_lists.append({name: real_url})
            if real_lists:
                tasks = []
                for real_ in real_lists:
                    for key, value in real_.items():
                        task = asyncio.ensure_future(
                            pingM3u(session, value, real_dict, key, sem, mintimeout, maxTimeout))
                        tasks.append(task)
                await asyncio.gather(*tasks)
                if real_dict:
                    isOne = len(arr) == 1
                    if isOne:
                        for key, value in real_dict.items():
                            if arr[0] == key:
                                # 有效直播源,名字/id
                                m3u_dict[id] = value
                                return
                    else:
                        for i in range(len(arr) - 1):
                            for key, value in real_dict.items():
                                if arr[i] == key:
                                    m3u_dict[id] = value
                                    return
                    return
            return
    except Exception as e:
        print(f"huya An error occurred while processing {id}. Error: {e}")


async def download_files4_single(ids, mintimeout, maxTimeout):
    m3u_dict = {}
    try:
        sem = asyncio.Semaphore(1000)  # 限制TCP连接的数量为100个
        async with aiohttp.ClientSession() as session:
            tasks = []
            for id in ids:
                task = asyncio.ensure_future(grab(session, id, m3u_dict, sem, mintimeout, maxTimeout))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files4():
    global redisKeyYoutube
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    ids = redisKeyYoutube.keys()
    m3u_dict = await download_files4_single(ids, mintimeout, maxTimeout)
    return m3u_dict


youtubeUrl = 'https://www.youtube.com/watch?v='


async def get_resolution(session, liveurl, sem, mintimeout, maxTimeout):
    try:
        async with sem, session.get(liveurl, timeout=mintimeout) as response:
            playlist_text = await response.text()
    except asyncio.TimeoutError:
        async with sem, session.get(liveurl, timeout=maxTimeout) as response:
            playlist_text = await response.text()
    playlist = m3u8.loads(playlist_text)
    playlists = playlist.playlists
    if len(playlists) < 1:
        return None
    highest_resolution = 0
    url = ''
    for item in playlists:
        resolution = item.stream_info.resolution[0] * item.stream_info.resolution[1]
        if resolution > highest_resolution:
            highest_resolution = resolution
            url = item.uri
    return url


async def grab(session, id, m3u_dict, sem, mintimeout, maxTimeout):
    try:
        url = youtubeUrl + id
        try:
            async with sem, session.get(url, timeout=mintimeout) as response:
                content = await response.text()
                if '.m3u8' not in content:
                    async with sem, session.get(url, timeout=maxTimeout) as response2:
                        content = await response2.text()
                        if '.m3u8' not in content:
                            return
        except asyncio.TimeoutError:
            async with sem, session.get(url, timeout=maxTimeout) as response:
                content = await response.text()
                if '.m3u8' not in content:
                    return
        end = content.find('.m3u8') + 5
        tuner = 100
        highest_quality_link = None
        while True:
            if 'https://' in content[end - tuner: end]:
                link = content[end - tuner: end]
                start = link.find('https://')
                end = link.find('.m3u8') + 5
                match = await get_resolution(session, link[start: end], sem, mintimeout, maxTimeout)
                if match:
                    highest_quality_link = match
                break
            else:
                tuner += 5
        if highest_quality_link:
            m3u_dict[id] = highest_quality_link
            # print(highest_quality_link)
        else:
            m3u_dict[id] = link[start: end]
    except Exception as e:
        print(f"youtube An error occurred while processing {id}. Error: {e}")


# 生成全部bilibili直播源
@app.route('/api/chaoronghe25', methods=['GET'])
@requires_auth
def chaoronghe_bilibili():
    return chaoronghe25()


def chaoronghe25():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        m3u_dict = loop.run_until_complete(download_files5())
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        global redisKeyBililiM3u
        global redisKeyBilili
        redisKeyBililiM3uFake = {}
        redisKeyBililiM3u.clear()
        redis_del_map(REDIS_KEY_BILIBILI_M3U)
        # fakeurl:192.168.5.1:22771/bilibili?id=xxxxx
        fakeurl = f"http://{ip}:{port_live}/bilibili/"
        for id, url in m3u_dict.items():
            try:
                redisKeyBililiM3u[id] = url
                name = redisKeyBilili[id]
                link = f'#EXTINF:-1 group-title="Bilibili"  tvg-name="{name}",{name}\n'
                redisKeyBililiM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyBililiM3uFake, f"{secret_path}bilibili.m3u", 10)
        redis_add_map(REDIS_KEY_BILIBILI_M3U, redisKeyBililiM3u)
        fuck_m3u_to_txt(f"{secret_path}bilibili.m3u", f"{secret_path}bilibili.txt")
        return "result"
    except Exception as e:
        return "empty"

# 生成全部huyta直播源
@app.route('/api/chaoronghe26', methods=['GET'])
@requires_auth
def chaoronghe_huya():
    return chaoronghe26()


def chaoronghe26():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # 有效直播源,名字/id
        m3u_dict = loop.run_until_complete(download_files6())
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        global redisKeyHuyaM3u
        global redisKeyHuya
        redisKeyHuyaM3uFake = {}
        redisKeyHuyaM3u.clear()
        redis_del_map(REDIS_KEY_HUYA_M3U)
        # fakeurl:192.168.5.1:22771/huya?id=xxxxx
        fakeurl = f"http://{ip}:{port_live}/huya/"
        for id, url in m3u_dict.items():
            try:
                redisKeyHuyaM3u[id] = url
                name = redisKeyHuya[id]
                link = f'#EXTINF:-1 group-title="Huya"  tvg-name="{name}",{name}\n'
                redisKeyHuyaM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyHuyaM3uFake, f"{secret_path}huya.m3u", 10)
        redis_add_map(REDIS_KEY_HUYA_M3U, redisKeyHuyaM3u)
        fuck_m3u_to_txt(f"{secret_path}huya.m3u", f"{secret_path}huya.txt")
        return "result"
    except Exception as e:
        return "empty"


# 生成全部YY直播源
@app.route('/api/chaoronghe27', methods=['GET'])
@requires_auth
def chaoronghe_yy():
    return chaoronghe27()


def chaoronghe27():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # 有效直播源,名字/id
        m3u_dict = loop.run_until_complete(download_files7())
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        global redisKeyYYM3u
        global redisKeyYY
        redisKeyYYM3uFake = {}
        redisKeyYYM3u.clear()
        redis_del_map(REDIS_KEY_YY_M3U)
        # fakeurl:192.168.5.1:22771/YY?id=xxxxx
        fakeurl = f"http://{ip}:{port_live}/YY/"
        for id, url in m3u_dict.items():
            try:
                redisKeyYYM3u[id] = url
                name = redisKeyYY[id]
                link = f'#EXTINF:-1 group-title="YY"  tvg-name="{name}",{name}\n'
                redisKeyYYM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyYYM3uFake, f"{secret_path}YY.m3u", 10)
        redis_add_map(REDIS_KEY_YY_M3U, redisKeyYYM3u)
        fuck_m3u_to_txt(f"{secret_path}YY.m3u", f"{secret_path}YY.txt")
        return "result"
    except Exception as e:
        return "empty"


# 生成全部youtube直播源
@app.route('/api/chaoronghe24', methods=['GET'])
@requires_auth
def chaoronghe_youtube():
    return chaoronghe24()


def chaoronghe24():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        m3u_dict = loop.run_until_complete(download_files4())
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        ip = init_IP()
        global redisKeyYoutubeM3u
        global redisKeyYoutube
        redisKeyYoutubeM3u.clear()
        redis_del_map(REDIS_KEY_YOUTUBE_M3U)
        redisKeyYoutubeM3uFake = {}
        # fakeurl:192.168.5.1:22771/youtube?id=xxxxx
        fakeurl = f"http://{ip}:{port_live}/youtube/"
        for id, url in m3u_dict.items():
            try:
                redisKeyYoutubeM3u[id] = url
                name = redisKeyYoutube[id]
                link = f'#EXTINF:-1 group-title="Youtube Live"  tvg-name="{name}",{name}\n'
                redisKeyYoutubeM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyYoutubeM3uFake, f"{secret_path}youtube.m3u", 10)
        redis_add_map(REDIS_KEY_YOUTUBE_M3U, redisKeyYoutubeM3u)
        fuck_m3u_to_txt(f"{secret_path}youtube.m3u", f"{secret_path}youtube.txt")
        return "result"
    except Exception as e:
        return "empty"


# 一键导出全部配置
def delete_all_items_in_db(file_paths):
    for path in file_paths:
        if os.path.exists(path):
            os.remove(path)


@app.route('/api/download_json_file7', methods=['GET'])
@requires_auth
def download_json_file7():
    file_paths = []
    # 生成JSON文件数据
    json_data = generate_multi_json_string(allListArr)
    if os.path.exists(f"{secret_path}allData.json"):
        os.remove(f"{secret_path}allData.json")
    # 保存JSON数据到临时文件
    with open(f"{secret_path}allData.json", 'w') as f:
        f.write(json_data)
    file_paths.append(f"{secret_path}allData.json")
    getHugeDataList(file_paths)
    # 发送所有JSON文件到前端
    result = send_multiple_files(file_paths)
    # 删除所有数据项
    delete_all_items_in_db(file_paths)
    return result


def getHugeDataList(file_paths):
    for redisKey in hugeDataList:
        try:
            # 生成JSON文件数据
            json_data = generate_json_string(redisKey)
            filename = f"{secret_path}{redisKey}.json"
            if os.path.exists(filename):
                os.remove(filename)
            # 保存JSON数据到临时文件
            with open(filename, 'w') as f:
                f.write(json_data)
            file_paths.append(filename)
        except Exception as e:
            pass


def send_multiple_files(file_paths):
    zip_path = os.path.join(secret_path, "allData.zip")
    # 将所有文件压缩成zip文件
    with zipfile.ZipFile(zip_path, 'w') as zip_file:
        for file_path in file_paths:
            zip_file.write(file_path, arcname=os.path.basename(file_path))
    # 发送zip文件到前端
    return send_file(zip_path, as_attachment=True)


# 删除密码
@app.route('/api/deletewm3u6', methods=['POST'])
@requires_auth
def deletewm3u6():
    return dellist(request, REDIS_KEY_PASSWORD_LINK)


# 添加密码
@app.route('/api/addnewm3u6', methods=['POST'])
@requires_auth
def addnewm3u6():
    return addlist(request, REDIS_KEY_PASSWORD_LINK)


# 拉取全部密码
@app.route('/api/getall6', methods=['GET'])
@requires_auth
def getall6():
    return jsonify(redis_get_map(REDIS_KEY_PASSWORD_LINK))


# 全部ipv6订阅链接超融合
@app.route('/api/chaoronghe5', methods=['GET'])
@requires_auth
def chaoronghe_ipv6():
    return chaoronghe5()


def chaoronghe5():
    try:
        return chaorongheBase(REDIS_KEY_WHITELIST_IPV6_LINK, 'process_data_abstract6',
                              REDIS_KEY_WHITELIST_IPV6_DATA, f"{secret_path}{getFileNameByTagName('ipv6')}.txt")
    except:
        return "empty"


# 拉取全部ipv6订阅
@app.route('/api/getall5', methods=['GET'])
@requires_auth
def getall5():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_IPV6_LINK))


# 删除ipv6订阅
@app.route('/api/deletewm3u5', methods=['POST'])
@requires_auth
def deletewm3u5():
    return dellist(request, REDIS_KEY_WHITELIST_IPV6_LINK)


# 添加ipv6订阅
@app.route('/api/addnewm3u5', methods=['POST'])
@requires_auth
def addnewm3u5():
    return addlist(request, REDIS_KEY_WHITELIST_IPV6_LINK)


# 删除ipv4订阅
@app.route('/api/deletewm3u4', methods=['POST'])
@requires_auth
def deletewm3u4():
    return dellist(request, REDIS_KEY_WHITELIST_IPV4_LINK)


# 添加ipv4订阅
@app.route('/api/addnewm3u4', methods=['POST'])
@requires_auth
def addnewm3u4():
    return addlist(request, REDIS_KEY_WHITELIST_IPV4_LINK)


# 全部ipv4订阅链接超融合
@app.route('/api/chaoronghe4', methods=['GET'])
@requires_auth
def chaoronghe_ipv4():
    return chaoronghe4()


def chaoronghe4():
    try:
        return chaorongheBase(REDIS_KEY_WHITELIST_IPV4_LINK, 'process_data_abstract5',
                              REDIS_KEY_WHITELIST_IPV4_DATA, f"{secret_path}{getFileNameByTagName('ipv4')}.txt")
    except:
        return "empty"


# 拉取全部ipv4订阅
@app.route('/api/getall4', methods=['GET'])
@requires_auth
def getall4():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_IPV4_LINK))


# 全部域名黑名单订阅链接超融合
@app.route('/api/chaoronghe3', methods=['GET'])
@requires_auth
def chaoronghe_blacklist():
    return chaoronghe3()


def chaoronghe3():
    try:
        return chaorongheBase(REDIS_KEY_BLACKLIST_LINK, 'process_data_abstract7',
                              REDIS_KEY_BLACKLIST_OPENCLASH_FALLBACK_FILTER_DOMAIN_DATA,
                              f"{secret_path}{getFileNameByTagName('openclashFallbackFilterDomain')}.conf")
        # return chaorongheBase(REDIS_KEY_BLACKLIST_LINK, 'process_data_abstract2',
        #                       REDIS_KEY_BLACKLIST_DATA, "/C.txt")
    except:
        return "empty"


# 删除黑名单订阅
@app.route('/api/deletewm3u3', methods=['POST'])
@requires_auth
def deletewm3u3():
    return dellist(request, REDIS_KEY_BLACKLIST_LINK)


# 添加黑名单订阅
@app.route('/api/addnewm3u3', methods=['POST'])
@requires_auth
def addnewm3u3():
    return addlist(request, REDIS_KEY_BLACKLIST_LINK)


# 拉取全部黑名单订阅
@app.route('/api/getall3', methods=['GET'])
@requires_auth
def getall3():
    return jsonify(redis_get_map(REDIS_KEY_BLACKLIST_LINK))


# 全部域名白名单订阅链接超融合
@app.route('/api/chaoronghe2', methods=['GET'])
@requires_auth
def chaoronghe_whitelist():
    return chaoronghe2()


def chaoronghe2():
    try:
        # chaorongheBase(REDIS_KEY_WHITELIST_LINK, 'process_data_abstract4',
        #                REDIS_KEY_DOMAIN_DATA, "/WhiteDomain.txt")
        return chaorongheBase(REDIS_KEY_WHITELIST_LINK, 'process_data_abstract3',
                              REDIS_KEY_WHITELIST_DATA_DNSMASQ,
                              f"{secret_path}{getFileNameByTagName('whiteListDnsmasq')}.conf")
        # return chaorongheBase(REDIS_KEY_WHITELIST_LINK, 'process_data_abstract2',
        #                       REDIS_KEY_WHITELIST_DATA, "/B.txt")
    except:
        return "empty"


# 拉取全部白名单订阅
@app.route('/api/getall2', methods=['GET'])
@requires_auth
def getall2():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_LINK))


# 添加白名单订阅
@app.route('/api/addnewm3u2', methods=['POST'])
@requires_auth
def addnewm3u2():
    return addlist(request, REDIS_KEY_WHITELIST_LINK)


# 删除白名单订阅
@app.route('/api/deletewm3u2', methods=['POST'])
@requires_auth
def deletewm3u2():
    return dellist(request, REDIS_KEY_WHITELIST_LINK)


# 删除全部本地直播源
@app.route('/api/removeallm3u', methods=['GET'])
@requires_auth
def removeallm3u():
    redis_del_map(REDIS_KEY_M3U_DATA)
    return "success"


# 删除全部加密订阅密码历史记录
@app.route('/api/removem3ulinks14', methods=['GET'])
@requires_auth
def removem3ulinks14():
    redis_del_map(REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS)
    return "success"


# 删除全部简易DNS黑名单
@app.route('/api/removem3ulinks13', methods=['GET'])
@requires_auth
def removem3ulinks13():
    redis_del_map(REDIS_KEY_DNS_SIMPLE_BLACKLIST)
    redis_add(REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG, 1)
    return "success"


# 删除全部youtube直播源
@app.route('/api/removem3ulinks24', methods=['GET'])
@requires_auth
def removem3ulinks24():
    redisKeyYoutube.clear()
    redis_del_map(REDIS_KEY_YOUTUBE)
    redisKeyYoutubeM3u.clear()
    redis_del_map(REDIS_KEY_YOUTUBE_M3U)
    return "success"


# 删除全部bilibili直播源
@app.route('/api/removem3ulinks25', methods=['GET'])
@requires_auth
def removem3ulinks25():
    redisKeyBilili.clear()
    redis_del_map(REDIS_KEY_BILIBILI)
    redisKeyBililiM3u.clear()
    redis_del_map(REDIS_KEY_BILIBILI_M3U)
    return "success"

# 删除全部huya直播源
@app.route('/api/removem3ulinks26', methods=['GET'])
@requires_auth
def removem3ulinks26():
    redisKeyHuya.clear()
    redis_del_map(REDIS_KEY_HUYA)
    redisKeyHuyaM3u.clear()
    redis_del_map(REDIS_KEY_HUYA_M3U)
    return "success"


# 删除全部YY直播源
@app.route('/api/removem3ulinks27', methods=['GET'])
@requires_auth
def removem3ulinks27():
    redisKeyYY.clear()
    redis_del_map(REDIS_KEY_YY)
    redisKeyYYM3u.clear()
    redis_del_map(REDIS_KEY_YY_M3U)
    return "success"



# 删除全部简易DNS白名单
@app.route('/api/removem3ulinks12', methods=['GET'])
@requires_auth
def removem3ulinks12():
    redis_del_map(REDIS_KEY_DNS_SIMPLE_WHITELIST)
    redis_add(REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG, 1)
    return "success"


# 删除全部M3U白名单
@app.route('/api/removem3ulinks11', methods=['GET'])
@requires_auth
def removem3ulinks11():
    m3u_whitlist.clear()
    redis_del_map(REDIS_KEY_M3U_WHITELIST)
    return "success"


# 删除全部M3U白名单分组优先级
@app.route('/api/removem3ulinks16', methods=['GET'])
@requires_auth
def removem3ulinks16():
    m3u_whitlist_rank.clear()
    ranked_m3u_whitelist_set.clear()
    redis_del_map(REDIS_KEY_M3U_WHITELIST_RANK)
    return "success"


# 删除全部下载加密上传
@app.route('/api/removem3ulinks17', methods=['GET'])
@requires_auth
def removem3ulinks17():
    downAndSecUploadUrlPassAndName.clear()
    redis_del(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME)
    return "success"


# 删除全部下载解密
@app.route('/api/removem3ulinks18', methods=['GET'])
@requires_auth
def removem3ulinks18():
    downAndDeSecUrlPassAndName.clear()
    redis_del(REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME)
    return "success"


# 删除全部M3U黑名单
@app.route('/api/removem3ulinks15', methods=['GET'])
@requires_auth
def removem3ulinks15():
    m3u_blacklist.clear()
    redis_del_map(REDIS_KEY_M3U_BLACKLIST)
    return "success"


# 删除全部节点后端服务器配置
@app.route('/api/removem3ulinks10', methods=['GET'])
@requires_auth
def removem3ulinks10():
    redis_del_map(REDIS_KEY_PROXIES_SERVER)
    redis_del_map(REDIS_KEY_PROXIES_SERVER_CHOSEN)
    initProxyServer()
    return "success"


# 删除全部节点远程配置订阅
@app.route('/api/removem3ulinks9', methods=['GET'])
@requires_auth
def removem3ulinks9():
    redis_del_map(REDIS_KEY_PROXIES_MODEL)
    redis_del_map(REDIS_KEY_PROXIES_MODEL_CHOSEN)
    initProxyModel()
    return "success"


# 删除全部节点订阅
@app.route('/api/removem3ulinks8', methods=['GET'])
@requires_auth
def removem3ulinks8():
    redis_del_map(REDIS_KEY_PROXIES_LINK)
    return "success"


# 删除全部密码本
@app.route('/api/removem3ulinks6', methods=['GET'])
@requires_auth
def removem3ulinks6():
    redis_del_map(REDIS_KEY_PASSWORD_LINK)
    return "success"


# 删除全部ipv6订阅链接
@app.route('/api/removem3ulinks5', methods=['GET'])
@requires_auth
def removem3ulinks5():
    redis_del_map(REDIS_KEY_WHITELIST_IPV6_LINK)
    return "success"


# 删除全部ipv4订阅链接
@app.route('/api/removem3ulinks4', methods=['GET'])
@requires_auth
def removem3ulinks4():
    redis_del_map(REDIS_KEY_WHITELIST_IPV4_LINK)
    return "success"


# 删除全部白名单源订阅链接
@app.route('/api/removem3ulinks3', methods=['GET'])
@requires_auth
def removem3ulinks3():
    redis_del_map(REDIS_KEY_BLACKLIST_LINK)
    return "success"


# 删除全部白名单源订阅链接
@app.route('/api/removem3ulinks2', methods=['GET'])
@requires_auth
def removem3ulinks2():
    redis_del_map(REDIS_KEY_WHITELIST_LINK)
    return "success"


# 删除全部直播源订阅链接
@app.route('/api/removem3ulinks', methods=['GET'])
@requires_auth
def removem3ulinks():
    redis_del_map(REDIS_KEY_M3U_LINK)
    return "success"


# 导出本地永久直播源
@app.route('/api/download_m3u_file', methods=['GET'])
@requires_auth
def download_m3u_file():
    my_dict = redis_get_map(REDIS_KEY_M3U_DATA)
    distribute_data(my_dict, f"{secret_path}temp_m3u.m3u", 10)
    # 发送JSON文件到前端
    return send_file(f"{secret_path}temp_m3u.m3u", as_attachment=True)


# 手动上传m3u文件把直播源保存到数据库
@app.route('/api/upload_m3u_file', methods=['POST'])
@requires_auth
def upload_m3u_file():
    file = request.files['file']
    # file_content = file.read().decode('utf-8')
    file_content = file.read()
    # file_content = read_file_with_encoding(file)
    my_dict = formatdata_multithread(file_content.splitlines(), 10)
    # my_dict = formattxt_multithread(file_content.splitlines(), 100)
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    if len(tmp_url_tvg_name_dict.keys()) > 0:
        redis_add_map(REDIS_KET_TMP_CHINA_CHANNEL, tmp_url_tvg_name_dict)
        tmp_url_tvg_name_dict.clear()
    return '文件已上传'


# 删除直播源
@app.route('/api/deletem3udata', methods=['POST'])
@requires_auth
def deletem3udata():
    # 获取 HTML 页面发送的 POST 请求参数
    deleteurl = request.json.get('deleteurl')
    r.hdel('localm3u', deleteurl)
    return jsonify({'deletem3udata': "delete success"})


# 添加直播源
@app.route('/api/addm3udata', methods=['POST'])
@requires_auth
def addm3udata():
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    my_dict = {addurl: name}
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    return jsonify({'addresult': "add success"})


# 拉取全部本地直播源
@app.route('/api/getm3udata', methods=['GET'])
@requires_auth
def getm3udata():
    return jsonify(redis_get_map(REDIS_KEY_M3U_DATA))


# 添加直播源到本地
@app.route('/api/savem3uarea', methods=['POST'])
@requires_auth
def savem3uarea():
    # 获取 HTML 页面发送的 POST 请求参数
    m3utext = request.json.get('m3utext')
    # 格式优化
    my_dict = formattxt_multithread(m3utext.split("\n"), 'process_data_abstract')
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    return jsonify({'addresult': "add success"})


# 添加直播源订阅
@app.route('/api/addnewm3u', methods=['POST'])
@requires_auth
def addnewm3u():
    return addlist(request, REDIS_KEY_M3U_LINK)


# 删除直播源订阅
@app.route('/api/deletewm3u', methods=['POST'])
@requires_auth
def deletewm3u():
    return dellist(request, REDIS_KEY_M3U_LINK)


# 拉取全部直播源订阅
@app.route('/api/getall', methods=['GET'])
@requires_auth
def getall():
    return jsonify(redis_get_map(REDIS_KEY_M3U_LINK))


# 全部m3u订阅链接超融合
@app.route('/api/chaoronghe', methods=['GET'])
@requires_auth
def chaoronghe_m3u():
    return chaoronghe()


def chaoronghe():
    try:
        return chaorongheBase(REDIS_KEY_M3U_LINK, 'process_data_abstract', REDIS_KEY_M3U_DATA,
                              f"{secret_path}{getFileNameByTagName('allM3u')}.m3u")
    except:
        return "empty"


# 手动上传m3u文件格式化统一转换
@app.route('/api/process-file', methods=['POST'])
@requires_auth
def process_file():
    file = request.files['file']
    # file_content = file.read().decode('utf-8')
    file_content = file.read()
    # file_content = read_file_with_encoding(file)
    my_dict = formatdata_multithread(file_content.splitlines(), 10)
    # my_dict = formattxt_multithread(file_content.splitlines(), 100)
    # my_dict = formatdata_multithread(file.readlines(), 100)
    distribute_data(my_dict, f"{secret_path}tmp.m3u", 10)
    return send_file(f"{secret_path}tmp.m3u", as_attachment=True)


# 手动上传m3u文件提取名字统一分组
@app.route('/api/process-file2', methods=['POST'])
@requires_auth
def process_file2():
    file = request.files['file']
    file_content = file.read()
    group = request.form.get('data')
    datalist = []
    for line in file_content.splitlines():
        datalist.append(decode_bytes(line).strip())
    file_content = "\n".join(datalist)
    regex_pattern = r'tvg-name="(.*?)"'
    all_matches = re.findall(regex_pattern, file_content)
    group_dict = {}
    for i in all_matches:
        group_dict[convert(i, 'zh-tw')] = group
        group_dict[convert(i, 'zh-cn')] = group
    # 将字典转换为JSON字符串并返回
    json_str = json.dumps(group_dict)
    filename = f'{secret_path}group.json'
    if os.path.exists(filename):
        os.remove(filename)
    # 保存JSON数据到临时文件
    with open(filename, 'w') as f:
        f.write(json_str)
    return send_file(filename, as_attachment=True)


# 手动上传m3u文件提取名字统一分组
@app.route('/api/process-file3', methods=['POST'])
@requires_auth
def process_file3():
    file = request.files['file']
    file_content = file.read()
    group = request.form.get('data')
    group_dict = {}
    # 数据源，字典（词库+新分组名字），新分组名字
    find_m3u_name_txt(file_content.splitlines(), group_dict, group)
    # 将字典转换为JSON字符串并返回
    json_str = json.dumps(group_dict)
    filename = f'{secret_path}group.json'
    if os.path.exists(filename):
        os.remove(filename)
    # 保存JSON数据到临时文件
    with open(filename, 'w') as f:
        f.write(json_str)
    return send_file(filename, as_attachment=True)


# 手动上传m3u文件转换成txt文件
@app.route('/api/process-file4', methods=['POST'])
@requires_auth
def process_file4():
    file = request.files['file']
    file_content = file.read()
    # 数据源，字典（词库+新分组名字），新分组名字
    resultContent = m3uToTxt(file_content.splitlines())
    filename = f'{secret_path}source.txt'
    if os.path.exists(filename):
        os.remove(filename)
    # 保存JSON数据到临时文件
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(resultContent)
    return send_file(filename, as_attachment=True)


# 自动简易dns
def thread_recall_chaoronghe7(second):
    while True:
        if isOpenFunction('switch24'):
            chaoronghe7()
            chaoronghe8()
        time.sleep(second)


def main():
    init_db()
    timer_thread1 = threading.Thread(target=executeM3u, args=(7200,), daemon=True)
    timer_thread1.start()
    timer_thread2 = threading.Thread(target=executeWhitelist, args=(10800,), daemon=True)
    timer_thread2.start()
    timer_thread6 = threading.Thread(target=executeProxylist, args=(3600,), daemon=True)
    timer_thread6.start()
    timer_thread7 = threading.Thread(target=thread_recall_chaoronghe7, args=(600,), daemon=True)
    timer_thread7.start()
    # 启动工作线程消费上传数据至github
    t2 = threading.Thread(target=worker_github, daemon=True)
    t2.start()
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    finally:
        print("close")


if __name__ == '__main__':
    start = False
    while True:
        try:
            # 检查Redis连接状态
            r.ping()
            print('!!!!!!!!!!!!!!!!!!!!!!!Redis is ready main.py\n')
            start = True
            break
        except redis.ConnectionError:
            # 连接失败，等待一段时间后重试
            time.sleep(1)
    if start:
        main()

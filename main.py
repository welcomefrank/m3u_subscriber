import abc
import asyncio
import base64
import multiprocessing
import secrets
import string
import concurrent
import ipaddress
import json
import math
import os
import queue
import re
import atexit
import shutil
import signal
import subprocess
import uuid
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
from flask import Flask, jsonify, request, send_file, render_template, send_from_directory, redirect, \
    after_this_request, Response, current_app

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
    , 'maxTimeoutTsAlive': '30', 'maxTimeoutTsFree': '300', 'maxTimeoutM3u8Free': '300'}

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

# douyu直播源
REDIS_KEY_DOUYU = 'redisKeyDouyu'
# douyu直播源地址，频道名字
redisKeyDouyu = {}
# douyu真实m3u8地址
REDIS_KEY_DOUYU_M3U = 'redisKeyDouyuM3u'
# douyu频道名字,真实m3u8地址
redisKeyDouyuM3u = {}

# alist直播源
REDIS_KEY_ALIST = 'redisKeyAlist'
# alist直播源网站地址，网站名字
redisKeyAlist = {}
# alist真实m3u8地址
REDIS_KEY_Alist_M3U = 'redisKeyAlistM3u'
# alist uuid,真实m3u8地址
redisKeyAlistM3u = {}
# alist视频格式
REDIS_KEY_Alist_M3U_TYPE = 'redisKeyAlistM3uType'
# alist uuid,视频格式
redisKeyAlistM3uType = {}

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

REDIS_KEY_WEBDAV_M3U = 'redisKeyWebdavM3u'
redisKeyWebDavM3u = {'url': '', 'username': '', 'password': ''}

# webdav直播源真实地址
REDIS_KEY_WEBDAV_M3U_DICT_RAW = 'redisKeyWebdavM3uDictRaw'
# uuid,真实url
true_webdav_m3u_dict_raw = {}
# webdav视频格式
REDIS_KEY_webdav_M3U_TYPE = 'redisKeyWebdavM3uType'
# webdav uuid,视频格式
redisKeyWebdavM3uType = {}

# webdav路径备份
REDIS_KEY_WEBDAV_PATH_LIST = 'redisKeyWebdavPathList'
# 路径，备注
redisKeyWebDavPathList = {}
port_live = 22771
webdav_fake_url = {'url': ''}


def update_webdav_fake_url():
    ip = init_IP()
    fakeurl = f"http://{ip}:{port_live}/videos/"
    webdav_fake_url['url'] = fakeurl


def getNowWebDavFakeUrl():
    return webdav_fake_url['url']


NORMAL_REDIS_KEY = 'normalRedisKey'
# 全部有redis备份字典key-普通redis结构，重要且数据量比较少的
allListArr = [REDIS_KEY_M3U_LINK, REDIS_KEY_WHITELIST_LINK, REDIS_KEY_BLACKLIST_LINK, REDIS_KEY_WHITELIST_IPV4_LINK,
              REDIS_KEY_WHITELIST_IPV6_LINK, REDIS_KEY_PASSWORD_LINK, REDIS_KEY_PROXIES_LINK, REDIS_KEY_PROXIES_TYPE,
              REDIS_KEY_PROXIES_MODEL, REDIS_KEY_PROXIES_MODEL_CHOSEN, REDIS_KEY_PROXIES_SERVER,
              REDIS_KEY_PROXIES_SERVER_CHOSEN, REDIS_KEY_GITEE, REDIS_KEY_GITHUB,
              REDIS_KEY_SECRET_PASS_NOW, REDIS_KEY_WEBDAV, REDIS_KEY_FILE_NAME, REDIS_KEY_WEBDAV_M3U,
              REDIS_KEY_FUNCTION_DICT, REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS]

# 数据巨大的redis配置,一键导出时单独导出每个配置
hugeDataList = [REDIS_KEY_BILIBILI, REDIS_KEY_DNS_SIMPLE_WHITELIST, REDIS_KEY_DNS_SIMPLE_BLACKLIST, REDIS_KEY_YOUTUBE,
                REDIS_KEY_M3U_WHITELIST_RANK, REDIS_KEY_M3U_BLACKLIST, REDIS_KEY_M3U_WHITELIST, REDIS_KEY_HUYA,
                REDIS_KEY_YY, REDIS_KEY_WEBDAV_PATH_LIST, REDIS_KEY_DOUYU, REDIS_KEY_ALIST]

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
threadsNum = {REDIS_KEY_THREADS: 0}

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


@app.route('/')
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


# 路由douyu
@app.route('/douyu/<path:filename>')
def serve_files_douyu(filename):
    id = filename.split('.')[0]
    url = redisKeyDouyuM3u[id]

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


# 切片后的目录，此处需要替换为真实值
SLICES_DIR = "/app/slices"
# 切片异常目录
SLICES_DIR_ERR = "/app/slicesErr"

# 保存正在运行的ffmpeg进程列表
ffmpeg_processes = {}

# 创建一个共享变量用于存储ffmpeg进程对象
ffmpeg_process = subprocess.Popen(['ffmpeg', '-i', 'input.mp4', 'output.mp4'])


def start_ffmpeg(cmd):
    global ffmpeg_process
    try:
        # 启动ffmpeg进程并将其存储到共享字典中
        ffmpeg_process = subprocess.Popen(cmd, stdin=subprocess.PIPE, shell=True)
    except Exception as e:
        print(e)
        stop_ffmpeg()
        pass


def stop_ffmpeg():
    global ffmpeg_process
    try:
        if ffmpeg_process:
            # 强制结束任务
            ffmpeg_process.stdin.write(b'q')
            # 杀掉进程，不一定成功
            ffmpeg_process.kill()
            try:
                # 立即杀死进程
                os.kill(ffmpeg_process.pid, signal.SIGKILL)
            except Exception as e:
                pass
    except Exception as e:
        print(e)
        pass


def cleanupExit():
    stop_ffmpeg()


# 注册一个回调函数，在应用程序退出时杀死所有正在运行的ffmpeg进程
def cleanup(uuid):
    global ffmpeg_processes
    stop_ffmpeg()
    ffmpeg_processes = {key: value for key, value in ffmpeg_processes.items() if key == uuid}


# 确保销毁ffmpeg
atexit.register(cleanupExit)
recordPath = {'past': 'nope'}


# 看完一个ts就删除一个，删除已经看过超过60秒的
def safe_delete_single_ts(tsfies):
    # 已经过期的ts文件
    if len(tsfies) == 0:
        return
    if os.path.exists(SLICES_DIR):
        errPathList = []
        for removePath in tsfies:
            if os.path.exists(removePath):
                try:
                    os.remove(removePath)
                except Exception as e:
                    # 文件删不掉，移到异常文件夹干掉
                    if os.path.exists(removePath):
                        errPathList.append(removePath)
                    pass
        dealRemoveErrTsPath(errPathList)
        # 最终还是有文件没有移动成功，这部分异常数据还是存活了
        if len(errPathList) > 0:
            # 真正被删除掉的ts文件=已经过期的ts文件总文件-没有成功删除的文件
            result = [item for item in tsfies if item not in errPathList]
            # 已经过期的ts文件，真正被删除掉的
            tsfies.clear()
            tsfies.extend(result)


# 尽可能安全地删除切片
def safe_delete_ts(uuid):
    errPathList = []
    tmpAllRemoveList = []
    try:
        # 新的切片产生，删除全部其他切片
        if os.path.exists(SLICES_DIR):
            # 目录下全部文件
            removePaths = os.listdir(SLICES_DIR)
            for filename in removePaths:
                # 不是以uuid开始的文件，包括m3u8和ts文件
                if not filename.startswith(uuid):
                    removePath = os.path.join(SLICES_DIR, filename)
                    try:
                        os.remove(removePath)
                    except Exception as e:
                        # 文件删不掉，移到异常文件夹干掉
                        if os.path.exists(removePath):
                            errPathList.append(removePath)
                            tmpAllRemoveList.append(removePath)
                        pass
            if len(tmpAllRemoveList) > 0:
                # 不是uuid相关的文件，没有被完全删除掉
                dealRemoveErrTsPath(errPathList)
                # 最终还是有文件没有移动成功，这部分数据还是存活了
                if len(errPathList) > 0:
                    # 真正被删除掉的ts,m3u8文件=总删除文件-没有成功删除的文件
                    result = [item for item in tmpAllRemoveList if item not in errPathList]
                    # 已经过期的ts文件，真正被删除掉的
                    if len(result) > 0:
                        # 真正被删除掉的ts文件，从字典里删除
                        for key in result:
                            try:
                                del ts_dict[key]
                            except Exception as e:
                                pass
    except Exception as e:
        pass


def dealRemoveErrTsPath(errPathList):
    # 没有成功删除的文件
    if len(errPathList) > 0:
        # 没有异常文件夹则建立
        if not os.path.isdir(SLICES_DIR_ERR):
            try:
                os.makedirs(SLICES_DIR_ERR)
            except Exception as e:
                pass
        list = []
        for errFile in errPathList:
            # 把异常文件移到异常文件夹
            try:
                shutil.move(errFile, SLICES_DIR_ERR)
            except Exception as e:
                list.append(errFile)
                pass
        # 删除异常文件夹
        deletePathAndRebuild()
        # 最终还是有文件没有移动成功，这部分数据还是存活了
        if len(list) > 0:
            errPathList.clear()
            errPathList.extend(list)


def checkAndRemovePastData(uuid):
    global recordPath
    # 新的请求文件不是相同的，神父换碟了，终止ffmpeg,清除路径下全部数据
    oldname = recordPath['past']
    if oldname != uuid:
        try:
            # 关闭除新切片外的全部进程
            cleanup(uuid)
            # 新的切片产生，删除全部其他切片
            safe_delete_ts(uuid)
        except Exception as e:
            pass
        recordPath['past'] = uuid


# 删除异常文件夹
def deletePathAndRebuild():
    try:
        if os.path.isdir(SLICES_DIR_ERR):
            shutil.rmtree(SLICES_DIR_ERR)
        os.makedirs(SLICES_DIR_ERR)
    except Exception as e:
        # print(e)
        pass


slice_path_fail_default = os.path.join('/app/secret', f"none.ts")
# mp4
headers_default = {'Content-Type': 'application/vnd.apple.mpegurl',

                   'Expect': '100-continue',
                   'Connection': 'Keep-Alive'
                   }
headers_default_mp4 = {
    'Content-Type': 'video/mp4',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_mkv = {
    'Content-Type': 'video/x-matroska',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_avi = {
    'Content-Type': 'video/x-msvideo',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_rmvb = {
    'Content-Type': 'application/vnd.rn-realmedia-vbr',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_rm = {
    'Content-Type': 'application/vnd.rn-realmedia',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_mov = {
    'Content-Type': 'video/quicktime',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_mpg = {
    'Content-Type': 'video/mpeg',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_wmv = {
    'Content-Type': 'video/x-ms-wmv',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_m4v = {
    'Content-Type': 'video/x-m4v',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_mpeg = {
    'Content-Type': 'video/mpeg',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_3gp = {
    'Content-Type': 'video/3gpp',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}
headers_default_ts = {
    'Content-Type': 'video/mp2t',
    'Transfer-Encoding': 'chunked',
    'Expect': '100-continue',
    'Connection': 'Keep-Alive',
}

default_video_prefix = 'http://127.0.0.1:5000/videos/'
default_video_prefix_encode = default_video_prefix.encode()
default_video_prefix_fail = 'http://127.0.0.1:5000/videosfail/'
# default_video_prefix_encode_fail = default_video_prefix_fail.encode()
fail_m3u8 = f'#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-ALLOW-CACHE:YES\n#EXT-X-TARGETDURATION:19\n#EXTINF:18.160000,\n {default_video_prefix_fail}none.ts\n#EXT-X-ENDLIST\n'.encode()


# lock_m3u8 = threading.Lock()


# bug:ffmpeg写m3u8和读取它会产生竞争
@app.route('/videos/<path:path>.m3u8')
def video_m3u8(path):
    # with lock_m3u8:
    global ffmpeg_processes
    global redisKeyWebdavM3uType
    if path not in true_webdav_m3u_dict_raw.keys():
        # if path not in VIDEO_MAPPING.keys():
        return "Video not found", 404
    slices_dir = os.environ.get('SLICES_DIR', '/app/slices')
    if path not in ffmpeg_processes.keys():
        # 使用ffmpeg命令行工具对视频进行实时切片，并生成M3U8格式的播放列表文件
        slices_path = os.path.join(slices_dir,
                                   f"{path}_%05d.ts")
        if not os.path.isfile(slices_path % 1):
            credentials = f"{redisKeyWebDavM3u['username']}:{redisKeyWebDavM3u['password']}"
            encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
            hls_url = getNowWebDavFakeUrl()
            # hls_url = default_video_prefix
            try:
                videoType = redisKeyWebdavM3uType[path]
            except:
                videoType = 'mp4'
                pass
            if videoType == 'mp4':
                cmd = f"ffmpeg -headers \"Authorization: Basic {encoded_credentials}\" -i {true_webdav_m3u_dict_raw[path]} -c copy -map 0 -f hls -hls_time 10 -hls_list_size 0 -hls_base_url {hls_url} -hls_segment_filename {slices_path}  {os.path.join(slices_dir, path)}.m3u8"
            elif videoType == 'mkv':
                cmd = f"ffmpeg -headers \"Authorization: Basic {encoded_credentials}\" -i {true_webdav_m3u_dict_raw[path]} -c copy -map 0:v:0 -map 0:a:0  -map_chapters -1 -f hls -hls_time 10 -hls_list_size 0 -hls_base_url {hls_url} -hls_segment_filename {slices_path}  {os.path.join(slices_dir, path)}.m3u8"
            elif videoType == 'avi':
                cmd = f"ffmpeg -headers \"Authorization: Basic {encoded_credentials}\" -i {true_webdav_m3u_dict_raw[path]} -c copy -map 0:v:0 -map 0:a:0  -map_chapters -1 -f hls -hls_time 10 -hls_list_size 0 -hls_base_url {hls_url} -hls_segment_filename {slices_path}  {os.path.join(slices_dir, path)}.m3u8"
            else:
                cmd = f"ffmpeg -headers \"Authorization: Basic {encoded_credentials}\" -i {true_webdav_m3u_dict_raw[path]} -c copy -map 0 -f hls -hls_time 10 -hls_list_size 0 -hls_base_url {hls_url} -hls_segment_filename {slices_path}  {os.path.join(slices_dir, path)}.m3u8"

            # cmd = f"ffmpeg -headers \"Authorization: Basic {encoded_credentials}\" -i {true_webdav_m3u_dict_raw[path]} -c copy -map 0 -f segment -segment_list {os.path.join(slices_dir, path)}.m3u8 -segment_time 10 -hls_base_url {hls_url} {slices_path}"
            # process = subprocess.Popen(cmd, shell=True)
            checkAndRemovePastData(path)
            start_ffmpeg(cmd)
            ffmpeg_processes[path] = ''
    start_time = time.time()  # 获取当前时间戳
    # isSuccess = False
    while time.time() - start_time < 300:
        try:
            # 读取M3U8播放列表文件并返回给客户端
            with open(os.path.join(slices_dir, f"{path}.m3u8"), "rb") as f:
                m3u8_data = f.read()
            if len(m3u8_data) > 0:
                # isSuccess = True
                break
            time.sleep(1)
        except Exception as e:
            time.sleep(1)
            # print(e)
            continue
    # if not isSuccess:
    #     return Response(fail_m3u8, headers=headers_default)
    return Response(m3u8_data, headers=headers_default)


@app.route('/alist/<path:path>.m3u8')
def video_m3u8_alist(path):
    # with lock_m3u8:
    global ffmpeg_processes
    global redisKeyAlistM3uType
    if path not in redisKeyAlistM3u.keys():
        return "Video not found", 404
    slices_dir = os.environ.get('SLICES_DIR', '/app/slices')
    if path not in ffmpeg_processes.keys():
        # 使用ffmpeg命令行工具对视频进行实时切片，并生成M3U8格式的播放列表文件
        slices_path = os.path.join(slices_dir,
                                   f"{path}_%05d.ts")
        if not os.path.isfile(slices_path % 1):
            hls_url = getNowWebDavFakeUrl()
            # hls_url = default_video_prefix
            try:
                videoType = redisKeyAlistM3uType[path]
            except:
                videoType = 'mp4'
                pass
            if videoType == 'mp4':
                cmd = f"ffmpeg -i {redisKeyAlistM3u[path]} -c copy -map 0 -f hls -hls_time 10 -hls_list_size 0 -hls_base_url {hls_url} -hls_segment_filename {slices_path}  {os.path.join(slices_dir, path)}.m3u8"
            elif videoType == 'mkv':
                cmd = f"ffmpeg -i {redisKeyAlistM3u[path]} -c copy -map 0:v:0 -map 0:a:0  -map_chapters -1 -f hls -hls_time 10 -hls_list_size 0 -hls_base_url {hls_url} -hls_segment_filename {slices_path}  {os.path.join(slices_dir, path)}.m3u8"
            elif videoType == 'avi':
                cmd = f"ffmpeg -i {redisKeyAlistM3u[path]} -c copy -map 0:v:0 -map 0:a:0  -map_chapters -1 -f hls -hls_time 10 -hls_list_size 0 -hls_base_url {hls_url} -hls_segment_filename {slices_path}  {os.path.join(slices_dir, path)}.m3u8"
            else:
                cmd = f"ffmpeg -i {redisKeyAlistM3u[path]} -c copy -map 0 -f hls -hls_time 10 -hls_list_size 0 -hls_base_url {hls_url} -hls_segment_filename {slices_path}  {os.path.join(slices_dir, path)}.m3u8"
            checkAndRemovePastData(path)
            start_ffmpeg(cmd)
            ffmpeg_processes[path] = ''
    maxTimeoutM3u8Free = int(getFileNameByTagName('maxTimeoutM3u8Free'))
    start_time = time.time()  # 获取当前时间戳
    # isSuccess = False
    while time.time() - start_time < maxTimeoutM3u8Free:
        try:
            # 读取M3U8播放列表文件并返回给客户端
            with open(os.path.join(slices_dir, f"{path}.m3u8"), "rb") as f:
                m3u8_data = f.read()
            if len(m3u8_data) > 0:
                # isSuccess = True
                break
            time.sleep(1)
        except Exception as e:
            time.sleep(1)
            # print(e)
            continue
    # if not isSuccess:
    #     return Response(fail_m3u8, headers=headers_default)
    return Response(m3u8_data, headers=headers_default)


# 上一次切片记录时间
# 切片名字,时间戳，超过1分钟的切片全部删除
# mark 是特殊的，记录上一次访问ts时间
mark = 'ppap202359'
pastTs = {}
ts_dict = {mark: 0.0}


# ts前进一次，除了切片和第一次找不到是强制归0
def check_ts_jump(path):
    # 第一次找不到
    if 'past' in pastTs.keys():
        arr = pastTs['past'].split('_')
        arr2 = path.split('_')
        # 换片,从0开始
        if arr[0] != arr2[0]:
            lenNumber = len(arr2[1])
            i = 0
            str11 = arr2[0]
            str11 += '_'
            while i < lenNumber:
                i += 1
                str11 += '0'
            return str11
        oldNum = int(arr[1])
        nowNum = int(arr2[1])
        result = nowNum - oldNum
        # 正常叠加
        if result == 1:
            return path
        # 回跳\后跳、重复
        else:
            trueNum = str(oldNum + 1)
            lenNumber = len(arr[1])
            left = lenNumber - len(trueNum)
            i = 0
            str11 = arr[0]
            str11 += '_'
            while i < left:
                i += 1
                str11 += '0'
            str11 += trueNum
            return str11
    else:
        # 强制从0开始
        arr2 = path.split('_')
        lenNumber = len(arr2[1])
        i = 0
        str11 = arr2[0]
        str11 += '_'
        while i < lenNumber:
            i += 1
            str11 += '0'
        return str11


# lock = threading.Lock()


# 客户端读表，依据顺序读取ts,
# 读取失败-跳
# 多次请求相同ts-平1
# 读取完毕-重新拉取-回读+跳

# 解决办法:服务器记录ts序号，只增不减
# 锁记录修改
# 有开头，中间读条没有，跳
@app.route('/videos/<path:path>.ts')
def video_ts(path):
    # with lock:
    # ts前进一次，除了切片和第一次找不到是强制归0
    path2 = check_ts_jump(path)
    slice_path = os.path.join(SLICES_DIR, f"{path2}.ts")
    now = time.time()  # 获取当前时间戳
    maxTimeoutTsAlive = int(getFileNameByTagName('maxTimeoutTsAlive'))
    # 检查切片文件是否存在，如果不存在则返回404错误
    while time.time() - now < maxTimeoutTsAlive:
        if os.path.isfile(slice_path):
            break
        time.sleep(1)
        # video_ts(path2)
    # return video_ts_fail(path)
    # return video_ts(path2)
    # 使用Flask的send_file函数将切片文件作为流推送给客户端
    maxTimeoutTsFree = int(getFileNameByTagName('maxTimeoutTsFree'))
    while time.time() - now < maxTimeoutTsFree:
        try:
            # bug预防：判断文件存在但是不确定有没有线程占用，所以多次读取文件判断大小，如果不判断直接发送会导致异常ts流被客户端直接通过造成跳帧现象
            # 读取M3U8播放列表文件并返回给客户端
            with open(slice_path, "rb") as f1:
                ts_data1 = f1.read()
            if len(ts_data1) == 0:
                continue
            time.sleep(1)
            with open(slice_path, "rb") as f2:
                ts_data2 = f2.read()
            if ts_data1 == ts_data2:
                time.sleep(1)
                with open(slice_path, "rb") as f3:
                    ts_data3 = f3.read()
                if ts_data3 == ts_data2:
                    break
        except Exception as e:
            time.sleep(1)
            # print(e)
            continue
    now = time.time()
    # 记录当前记录的步骤ts
    pastTs['past'] = path2
    ts_dict[slice_path] = now
    # ts成功时间戳记录
    ts_dict[mark] = now
    return send_file(slice_path, mimetype='video/MP2T')


@app.route('/videosfail/<path:path>.ts')
def video_ts_fail(path):
    slice_path = os.path.join(secret_path, f"{path}.ts")
    # 检查切片文件是否存在，如果不存在则返回404错误
    if not os.path.isfile(slice_path):
        return "Slice not found", 404
    # 使用Flask的send_file函数将切片文件作为流推送给客户端
    return send_file(slice_path, mimetype='video/MP2T')


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
def upload_json(request, rediskey, filename):
    try:
        json_dict = json.loads(request.get_data())
        if rediskey not in specialRedisKey:
            redis_add_map(rediskey, json_dict)
            importToReloadCache(rediskey, json_dict)
        else:
            importToReloadCacheForSpecial(rediskey, json_dict)
        try:
            os.remove(filename)
        except Exception as e:
            pass
        return jsonify({'success': True})
    except Exception as e:
        print("An error occurred: ", e)
        return jsonify({'success': False})


# def execute(method_name, sleepSecond):
#     while True:
#         # m3u
#         if method_name == 'chaoronghe':
#             if not isOpenFunction('switch25'):
#                 time.sleep(sleepSecond)
#                 continue
#         # 域名白名单
#         elif method_name == 'chaoronghe2':
#             if not isOpenFunction('switch26'):
#                 time.sleep(sleepSecond)
#                 continue
#         # 域名黑名单
#         elif method_name == 'chaoronghe3':
#             if not isOpenFunction('switch13'):
#                 time.sleep(sleepSecond)
#                 continue
#         # ipv4
#         elif method_name == 'chaoronghe4':
#             if not isOpenFunction('switch27'):
#                 time.sleep(sleepSecond)
#                 continue
#         # ipv6
#         elif method_name == 'chaoronghe5':
#             if not isOpenFunction('switch28'):
#                 time.sleep(sleepSecond)
#                 continue
#         # 节点订阅
#         elif method_name == 'chaoronghe6':
#             if not isOpenFunction('switch29'):
#                 time.sleep(sleepSecond)
#                 continue
#         method = globals().get(method_name)
#         # 判断方法是否存在
#         if not method:
#             break
#         # 执行方法
#         method()
#         time.sleep(sleepSecond)


# 直播源线程阻塞开关
timer_condition_m3u = threading.Condition()
# 域名白名单线程阻塞开关
timer_condition_whitelist = threading.Condition()
# 域名黑名单线程阻塞开关
timer_condition_blacklist = threading.Condition()
# ipv4线程阻塞开关
timer_condition_ipv4list = threading.Condition()
# ipv6线程阻塞开关
timer_condition_ipv6list = threading.Condition()
# 节点订阅线程阻塞开关
timer_condition_proxylist = threading.Condition()
# 下载加密上传线程阻塞开关
timer_condition_downUpload = threading.Condition()
# 下载解密线程阻塞开关
timer_condition_download = threading.Condition()
# youtube直播源线程阻塞开关
timer_condition_youtube = threading.Condition()


def executeYoutube(sleepSecond):
    while True:
        with timer_condition_youtube:
            if not isOpenFunction('switch35'):
                timer_condition_youtube.wait(sleepSecond)
            # 执行方法
            chaoronghe24()
            chaoronghe25()
            chaoronghe26()
            chaoronghe27()
            chaoronghe29()
            print("youtube直播源定时器执行成功")
            timer_condition_youtube.wait(sleepSecond)
        time.sleep(sleepSecond)


def executeDown(sleepSecond):
    while True:
        with timer_condition_download:
            if not isOpenFunction('switch34'):
                timer_condition_download.wait(sleepSecond)
            # 执行方法
            chaoronghe10()
            print("下载解密定时器执行成功")
            timer_condition_download.wait(sleepSecond)
        time.sleep(sleepSecond)


def executeDownUpload(sleepSecond):
    while True:
        with timer_condition_downUpload:
            if not isOpenFunction('switch33'):
                timer_condition_downUpload.wait(sleepSecond)
            # 执行方法
            chaoronghe9()
            print("下载加密上传定时器执行成功")
            timer_condition_downUpload.wait(sleepSecond)
        time.sleep(sleepSecond)


def executeProxylist(sleepSecond):
    while True:
        with timer_condition_proxylist:
            if not isOpenFunction('switch29'):
                timer_condition_proxylist.wait(sleepSecond)
            # 执行方法
            chaoronghe6()
            timer_condition_proxylist.wait(sleepSecond)
        time.sleep(sleepSecond)


def executeIPV6list(sleepSecond):
    while True:
        with timer_condition_ipv6list:
            if not isOpenFunction('switch28'):
                timer_condition_ipv6list.wait(sleepSecond)
            # 执行方法
            chaoronghe5()
            timer_condition_ipv6list.wait(sleepSecond)
        time.sleep(sleepSecond)


def executeIPV4list(sleepSecond):
    while True:
        with timer_condition_ipv4list:
            if not isOpenFunction('switch27'):
                timer_condition_ipv4list.wait(sleepSecond)
            # 执行方法
            chaoronghe4()
            timer_condition_ipv4list.wait(sleepSecond)
        time.sleep(sleepSecond)


def executeBlacklist(sleepSecond):
    while True:
        with timer_condition_blacklist:
            if not isOpenFunction('switch13'):
                timer_condition_blacklist.wait(sleepSecond)
            # 执行方法
            chaoronghe3()
            timer_condition_blacklist.wait(sleepSecond)
        time.sleep(sleepSecond)


def executeWhitelist(sleepSecond):
    while True:
        with timer_condition_whitelist:
            if not isOpenFunction('switch26'):
                timer_condition_whitelist.wait(sleepSecond)
            # 执行方法
            chaoronghe2()
            timer_condition_whitelist.wait(sleepSecond)
        time.sleep(sleepSecond)


def toggle_m3u(functionId, value):
    global function_dict
    if functionId == 'switch24':
        function_dict[functionId] = str(value)
        redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
        redis_add(REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG, 1)
    elif functionId == 'switch25':
        with timer_condition_m3u:
            function_dict[functionId] = str(value)
            redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
            timer_condition_m3u.notify()
    elif functionId == 'switch26':
        with timer_condition_whitelist:
            function_dict[functionId] = str(value)
            redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
            timer_condition_whitelist.notify()
    elif functionId == 'switch13':
        with timer_condition_blacklist:
            function_dict[functionId] = str(value)
            redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
            timer_condition_blacklist.notify()
    elif functionId == 'switch27':
        with timer_condition_ipv4list:
            function_dict[functionId] = str(value)
            redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
            timer_condition_ipv4list.notify()
    elif functionId == 'switch28':
        with timer_condition_ipv6list:
            function_dict[functionId] = str(value)
            redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
            timer_condition_ipv6list.notify()
    elif functionId == 'switch29':
        with timer_condition_proxylist:
            function_dict[functionId] = str(value)
            redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
            timer_condition_proxylist.notify()
    elif functionId == 'switch33':
        with timer_condition_downUpload:
            function_dict[functionId] = str(value)
            redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
            timer_condition_downUpload.notify()
    elif functionId == 'switch34':
        with timer_condition_download:
            function_dict[functionId] = str(value)
            redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
            timer_condition_download.notify()
    elif functionId == 'switch35':
        with timer_condition_youtube:
            function_dict[functionId] = str(value)
            redis_add_map(REDIS_KEY_FUNCTION_DICT, function_dict)
            timer_condition_youtube.notify()


def executeM3u(sleepSecond):
    while True:
        with timer_condition_m3u:
            if not isOpenFunction('switch25'):
                timer_condition_m3u.wait(sleepSecond)
            # 执行方法
            chaoronghe()
            timer_condition_m3u.wait(sleepSecond)
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


# url-基础请求列表API地址(alist网站/alist/api/fs/list)
# path-迭代查询路径
# file_url_dict 已经捕获到的文件(只存储视频文件)
# 新的路径
async def getPathBase(site, url, path, future_path_set, sem, session, redisKeyAlistM3u, fakeurl, pathxxx, base_path,
                      redisKeyAlistM3uType):
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
                # 签名
                sign = item['sign']
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
                            if base_path != '/':
                                future_path = f'{site}d{base_path}{path}/{name}'
                            else:
                                future_path = f'{site}d{path}/{name}'
                            str1 = path.split('/')[-1]
                            groupName = f'Alist-{str1}'
                        else:
                            if base_path != '/':
                                future_path = f'{site}d{base_path}/{name}'
                            else:
                                future_path = f'{site}d/{name}'
                            groupName = 'Alist-无分组'
                        encoded_url = urllib.parse.quote(future_path, safe=':/')
                        if sign and sign != '':
                            encoded_url = f'{encoded_url}?sign={sign}'
                        link = f'#EXTINF:-1 group-title="{groupName}"  tvg-name="{name}",{name}\n'
                        str_id = str(uuid.uuid4())
                        redisKeyAlistM3u[str_id] = encoded_url
                        videotype = name.lower().split('.')[-1]
                        redisKeyAlistM3uType[str_id] = videotype
                        redis_add_map(REDIS_KEY_Alist_M3U, {str_id: encoded_url})
                        redis_add_map(REDIS_KEY_Alist_M3U_TYPE, {str_id: videotype})
                        fake_m3u8 = f'{fakeurl}{str_id}.m3u8'
                        async with aiofiles.open(pathxxx, 'a', encoding='utf-8') as f:  # 异步的方式写入内容
                            await f.write(f'{link}{fake_m3u8}\n')
    except Exception as e:
        pass


async def sluty_alist_hunter(alist_url_dict, redisKeyAlistM3u, fakeurl, pathxxx, redisKeyAlistM3uType):
    path = f"{secret_path}alist.m3u"
    if os.path.exists(path):
        os.remove(path)
    api_part = 'api/fs/list'
    api_me_base_path = 'api/me'
    # 需要迭代访问的路径
    future_path_set = set()

    sem = asyncio.Semaphore(1000)  # 限制TCP连接的数量为100个
    async with aiohttp.ClientSession() as session:
        for site in alist_url_dict.keys():
            if not site.endswith('/'):
                site += '/'
            base_path_url = site + api_me_base_path
            async with sem, session.get(base_path_url) as response:
                json_data = await response.json()
                base_path = json_data['data']['base_path']
            full_url = site + api_part
            await getPathBase(site, full_url, None, future_path_set, sem, session, redisKeyAlistM3u, fakeurl, pathxxx,
                              base_path, redisKeyAlistM3uType)

            async def process_path(pathbase):
                await getPathBase(site, full_url, pathbase, future_path_set, sem, session, redisKeyAlistM3u, fakeurl,
                                  pathxxx, base_path, redisKeyAlistM3uType
                                  )

            while len(future_path_set) > 0:
                tasks = [process_path(pathbase) for pathbase in future_path_set]
                future_path_set.clear()
                await asyncio.gather(*tasks)


def check_alist_file(alist_url_dict, redisKeyAlistM3u, fakeurl, pathxxx, redisKeyAlistM3uType):
    asyncio.run(sluty_alist_hunter(alist_url_dict, redisKeyAlistM3u, fakeurl, pathxxx, redisKeyAlistM3uType))


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
        path7 = f"{secret_path}webdav.m3u"
        path8 = f"{secret_path}douyu.m3u"
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
        if os.path.exists(path7):
            source += '\n'
            source += copyAndRename(path7).decode()
        if os.path.exists(path8):
            source += '\n'
            source += copyAndRename(path8).decode()
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
            if os.path.exists(path7):
                source2 += copyAndRename(path7).decode()
            if os.path.exists(path8):
                source2 += copyAndRename(path8).decode()
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
    if ism3u:
        if isOpenFunction('switch4'):
            if len(my_dict) > 0:
                distribute_data(my_dict, fileName, 10)
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


def worker_webdav():
    while True:
        # 从任务队列中获取一个任务
        task = task_queue_webdav.get()
        if task is None:
            continue
        # 执行上传文件操作
        file_name = task
        updateFileToWebDAV(file_name)
        time.sleep(10)


def worker_gitee():
    while True:
        # 从任务队列中获取一个任务
        task = task_queue.get()
        if task is None:
            continue
        # 执行上传文件操作
        file_name = task
        updateFileToGitee(file_name)
        time.sleep(10)


def worker_github():
    while True:
        # 从任务队列中获取一个任务
        task = task_queue_github.get()
        if task is None:
            continue
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
    init_webdav_m3u_True_Data()
    update_webdav_fake_url()
    safe_delete_ts('nope')


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
        # 节点订阅-定时器
        if 'switch29' not in keys:
            dict['switch29'] = '1'
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
            , 'switch28': '0', 'switch29': '1', 'switch30': '0', 'switch31': '0', 'switch32': '0', 'switch33': '0',
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
                    tvg_name = preline[last_comma_index + 1:].strip()
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
                    tvg_name = preline[last_comma_index + 1:].strip()
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
        tvg_name = s[last_comma_index + 1:].strip()
    except Exception as e:
        try:
            tvg_name = re.search(r'tvg-name="([^"]+)"', s)
            if tvg_name is None:
                raise ValueError("未找到 tvg-name 属性")
            tvg_name = tvg_name.group(1)
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
        tvg_name = s[last_comma_index + 1:].strip()
    except Exception as e:
        try:
            tvg_name = re.search(r'tvg-name="([^"]+)"', s)
            if tvg_name is None:
                raise ValueError("未找到 tvg-name 属性")
            tvg_name = tvg_name.group(1)
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
    REDIS_KEY_YY: 'redisKeyYY',
    REDIS_KEY_WEBDAV_M3U: 'redisKeyWebDavM3u',
    REDIS_KEY_WEBDAV_PATH_LIST: 'redisKeyWebDavPathList',
    REDIS_KEY_DOUYU: 'redisKeyDouyu',
    REDIS_KEY_ALIST: 'redisKeyAlist'
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


def download_json_file_base(redislinkKey, filename):
    # 生成JSON文件数据
    json_data = generate_json_string(redislinkKey)
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
            num = 100
            redis_add(REDIS_KEY_THREADS, num)
            threadsNum[REDIS_KEY_THREADS] = num
            redis_add(REDIS_KEY_UPDATE_THREAD_NUM_FLAG, 1)
        threadsNum[REDIS_KEY_THREADS] = num
    else:
        num = 100
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
        elif redisKey == REDIS_KEY_WEBDAV_M3U:
            init_webdav_m3u()
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
        elif redisKey in REDIS_KEY_WEBDAV_PATH_LIST:
            try:
                global redisKeyWebDavPathList
                redisKeyWebDavPathList.clear()
                dict = redis_get_map(REDIS_KEY_WEBDAV_PATH_LIST)
                if dict:
                    redisKeyWebDavPathList.update(dict)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_DOUYU:
            try:
                global redisKeyDouyu
                global redisKeyDouyuM3u
                redisKeyDouyu.clear()
                dict = redis_get_map(REDIS_KEY_DOUYU)
                if dict:
                    redisKeyDouyu.update(dict)
                dict2 = redis_get_map(REDIS_KEY_DOUYU_M3U)
                if dict2:
                    redisKeyDouyuM3u.update(dict2)
            except Exception as e:
                pass
        elif redisKey in REDIS_KEY_ALIST:
            try:
                global redisKeyAlist
                global redisKeyAlistM3u
                global redisKeyAlistM3uType
                redisKeyAlist.clear()
                dict = redis_get_map(REDIS_KEY_ALIST)
                if dict:
                    redisKeyAlist.update(dict)
                redisKeyAlistM3u.clear()
                dict2 = redis_get_map(REDIS_KEY_Alist_M3U)
                if dict2:
                    redisKeyAlistM3u.update(dict2)
                redisKeyAlistM3uType.clear()
                dict3 = redis_get_map(REDIS_KEY_Alist_M3U_TYPE)
                if dict3:
                    redisKeyAlistM3uType.update(dict3)
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
        dict = {'动画杂烩': '', '巨兵长城': '', '车载': '', "DJ音乐": '', '舞曲': '', '炫动卡通': '',
                '金鹰卡通': '', '卡酷少儿': '', '优漫卡通': '', '浙江少儿': '', '河北少儿': '', '潍坊': ''
            , '黑莓动画': '', 'SPORTSWEAR': '', 'SPORTS WEAR': '', '汪汪队长': ''}
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
                "東森": "港澳台", "香港電視娛樂": "港澳台", "香港电视娱乐": "港澳台", "hoy tv": "港澳台",
                "ATV A1臺": "港澳台", "ATV A1台": "港澳台", "ATV WORLD": "港澳台",
                "Channel V HD": "港澳台", "Discovery Kids": "港澳台", "HOY TV": "港澳台", "ITV Granada": "港澳台",
                "J2": "港澳台", "NOW Sports": "港澳台", "Now Sports 2": "港澳台", "Now Sports 3": "港澳台",
                "Now Sports 5": "港澳台", "Now Sports 6": "港澳台", "Now Sports 7": "港澳台", "Now TV": "港澳台",
                "RTHK31": "港澳台", "RTHK32": "港澳台", "RTHK33": "港澳台", "RTHK34": "港澳台",
                "Sports Plus 1": "港澳台", "Star Sports2": "港澳台", "TVB E": "港澳台", "TVB J2": "港澳台",
                "TVB J2生活臺": "港澳台", "TVB J2生活台": "港澳台", "TVB 翡翠臺": "港澳台", "TVB 翡翠台": "港澳台",
                "TVB1(US)": "港澳台", "TVB娛樂新聞": "港澳台", "TVB娱乐新闻": "港澳台", "TVB新聞": "港澳台",
                "TVB新闻": "港澳台", "TVB星河": "港澳台", "TVB無線財經": "港澳台", "TVB无线财经": "港澳台",
                "TVB經典": "港澳台", "TVB经典": "港澳台", "Viu TV": "港澳台", "天威TVG": "港澳台", "天映經典": "港澳台",
                "天映经典": "港澳台", "天映頻道": "港澳台", "天映频道": "港澳台", "幸運88臺": "港澳台",
                "幸运88台": "港澳台", "有線18臺": "港澳台", "有线18台": "港澳台", "有線新聞": "港澳台",
                "有线新闻": "港澳台", "有線直播新聞": "港澳台", "有线直播新闻": "港澳台", "有線財經資訊臺": "港澳台",
                "有线财经资讯台": "港澳台", "港臺電影": "港澳台", "港台电影": "港澳台", "無線新聞臺": "港澳台",
                "无线新闻台": "港澳台", "無線財經臺": "港澳台", "无线财经台": "港澳台", "熱血時報": "港澳台",
                "热血时报": "港澳台", "翡翠臺": "港澳台", "翡翠台": "港澳台", "耀才財經臺": "港澳台",
                "耀才财经台": "港澳台", "財經資訊": "港澳台", "财经资讯": "港澳台", "香港國際財經臺": "港澳台",
                "香港国际财经台": "港澳台", "香港衛視": "港澳台", "香港卫视": "港澳台", "香港開電視": "港澳台",
                "香港开电视": "港澳台", "鳳凰Show": "港澳台", "凤凰Show": "港澳台", "鳳凰資訊HD": "港澳台",
                "凤凰资讯HD": "港澳台", "鳳凰電影": "港澳台", "凤凰电影": "港澳台", "鳳凰香港": "港澳台",
                "凤凰香港": "港澳台", "麵包臺": "港澳台", "面包台": "港澳台",
                "东森": "港澳台", "超視美洲": "港澳台", "超视美洲": "港澳台", "ETtoday": "港澳台", "高點綜合": "港澳台",
                "高点综合": "港澳台", "高點育樂": "港澳台", "高点育乐": "港澳台", "年代新聞": "港澳台",
                "年代新闻": "港澳台", "壹電視": "港澳台", "壹电视": "港澳台", "中天": "港澳台", "非凡新聞": "港澳台",
                "非凡新闻": "港澳台", "鳳凰衛視": "港澳台", "凤凰卫视": "港澳台", "鳳凰新聞": "港澳台",
                "凤凰新闻": "港澳台", "鳳凰資訊": "港澳台", "凤凰资讯": "港澳台", "鳳凰中文": "港澳台",
                "凤凰中文": "港澳台", "香港有線": "港澳台", "香港有线": "港澳台", "衛視合家歡": "港澳台",
                "卫视合家欢": "港澳台", "HBO": "美利坚合众国", "MYTV電影": "港澳台", "MYTV电影": "港澳台",
                "FRESH電影": "港澳台", "FRESH电影": "港澳台", "非凡商業": "港澳台", "非凡商业": "港澳台",
                "亞洲旅遊": "港澳台", "亚洲旅游": "港澳台", "亞洲綜合": "港澳台", "亚洲综合": "港澳台",
                "梅迪奇藝術": "港澳台", "梅迪奇艺术": "港澳台", "CINEMA影院": "港澳台", "博斯無限": "港澳台",
                "博斯无限": "港澳台", "香港國際": "港澳台", "香港国际": "港澳台", "星空衛視": "港澳台",
                "星空卫视": "港澳台", "澳視": "港澳台", "澳视": "港澳台", "唯心臺": "港澳台", "唯心台": "港澳台",
                "ViuTV": "港澳台", "Viutv": "港澳台", "功夫臺": "港澳台", "功夫台": "港澳台", "ELEVEN體育": "体育",
                "ELEVEN体育": "体育", "星河臺": "港澳台", "星河台": "港澳台", "星河頻道": "港澳台",
                "星河频道": "港澳台", "龍祥": "港澳台", "龙祥": "港澳台", "明珠臺": "港澳台", "明珠台": "港澳台",
                "鳳凰頻道": "港澳台", "凤凰频道": "港澳台", "港澳": "港澳台", "無線財經": "港澳台",
                "无线财经": "港澳台", "SMART知識": "港澳台", "SMART知识": "港澳台", "NHKWorld": "港澳台",
                "FOX": "港澳台", "FoodNetwork": "港澳台", "緯來": "港澳台", "纬来": "港澳台", "龍華動畫": "港澳台",
                "龙华动画": "港澳台", "龍華電影": "港澳台", "龙华电影": "港澳台", "龍華影劇": "港澳台",
                "龙华影剧": "港澳台", "國興衛視": "港澳台", "国兴卫视": "港澳台", "愛爾達": "港澳台",
                "爱尔达": "港澳台", "半島新聞": "美利坚合众国", "半岛新闻": "美利坚合众国", "龍華經典": "港澳台",
                "龙华经典": "港澳台", "壹新聞": "港澳台", "壹新闻": "港澳台", "華麗臺": "港澳台", "华丽台": "港澳台",
                "靖洋": "港澳台", "靖天": "港澳台", "樂活頻道": "港澳台", "乐活频道": "港澳台", "視納華仁": "港澳台",
                "视纳华仁": "港澳台", "採昌影劇": "港澳台", "采昌影剧": "港澳台", "華藝影劇": "港澳台",
                "华艺影剧": "港澳台", "華藝": "港澳台", "华艺": "港澳台", "智林體育": "港澳台", "智林体育": "港澳台",
                "Z頻道": "港澳台", "Z频道": "港澳台", "新唐人": "港澳台", "鏡電視": "港澳台", "镜电视": "港澳台",
                "十方法界": "港澳台", "華藏衛星": "港澳台", "华藏卫星": "港澳台", "世界電視": "港澳台",
                "世界电视": "港澳台", "希望綜合": "港澳台", "希望综合": "港澳台", "新天地民俗": "港澳台",
                "天美麗電視": "港澳台", "天美丽电视": "港澳台", "環宇新聞": "港澳台", "环宇新闻": "港澳台",
                "JET綜合": "港澳台", "JET综合": "港澳台", "東風衛視": "港澳台", "东风卫视": "港澳台",
                "TVB無線": "港澳台", "TVB无线": "港澳台", "亞洲新聞": "港澳台", "亚洲新闻": "港澳台",
                "耀才財經": "港澳台", "耀才财经": "港澳台", "有線財經": "港澳台", "有线财经": "港澳台",
                "正德電視": "港澳台", "正德电视": "港澳台", "雙子衛視": "港澳台", "双子卫视": "港澳台",
                "番薯衛星": "港澳台", "番薯卫星": "港澳台", "信吉藝文": "港澳台", "信吉艺文": "港澳台",
                "信吉衛星": "港澳台", "信吉卫星": "港澳台", "天良衛星": "港澳台", "天良卫星": "港澳台",
                "大立電視": "港澳台", "大立电视": "港澳台", "誠心電視": "港澳台", "诚心电视": "港澳台",
                "富立電視": "港澳台", "富立电视": "港澳台", "全大電視": "港澳台", "全大电视": "港澳台",
                "威達超舜": "港澳台", "威达超舜": "港澳台", "海豚綜合": "港澳台", "海豚综合": "港澳台",
                "冠軍電視": "港澳台", "冠军电视": "港澳台", "冠軍夢想臺": "港澳台", "冠军梦想台": "港澳台",
                "A-One體育": "港澳台", "A-One体育": "港澳台", "HOT頻道": "港澳台", "HOT频道": "港澳台",
                "彩虹E臺": "港澳台", "彩虹E台": "港澳台", "澳亞衛視": "港澳台", "澳亚卫视": "港澳台",
                "彩虹電影": "港澳台", "彩虹电影": "港澳台",
                "香蕉臺": "港澳台", "香蕉台": "港澳台",
                "好消息衛星": "港澳台", "好消息卫星": "港澳台", "好消息二臺": "港澳台", "好消息二台": "港澳台",
                "八大": "港澳台", "三立": "港澳台", "TVBS": "港澳台", "臺視": "港澳台", "台视": "港澳台",
                "中視": "港澳台", "中视": "港澳台", "國會頻道": "港澳台", "国会频道": "港澳台", "公視": "港澳台",
                "公视": "港澳台", "HKIBC": "港澳台", "港臺電視": "港澳台", "港台电视": "港澳台",
                "香港國際財經": "港澳台", "香港国际财经": "港澳台", "J2臺": "日本台", "J2台": "日本台",
                "Taiwan": "港澳台", "Medici-arts": "港澳台", "Hi-PLAY": "港澳台", "Love Nature 4K": "港澳台",
                "LS TIME": "港澳台", "MOMO": "港澳台", "iNEWS": "港澳台", "MTV": "港澳台", "港澳臺": "港澳台",
                "港澳台": "港澳台", "澳門": "港澳台", "澳门": "港澳台", "臺灣": "港澳台", "台湾": "港澳台",
                "鳳凰": "港澳台", "凤凰": "港澳台", "上視": "港澳台", "上视": "港澳台", "香港": "港澳台",
                "三臺電視": "港澳台", "三台电视": "港澳台", "人間": "港澳台", "人间": "港澳台", "大愛電視": "港澳台",
                "大爱电视": "港澳台", "龍華戲劇臺": "港澳台", "龙华戏剧台": "港澳台", "鳯凰": "港澳台",
                "天映": "港澳台", "亞旅": "港澳台", "亚旅": "港澳台", "八度空間": "港澳台", "八度空间": "港澳台",
                "ELTA體育": "体育", "ELTA体育": "体育", "愛達": "港澳台", "爱达": "港澳台", "波斯魅力臺": "港澳台",
                "波斯魅力台": "港澳台", "寰宇": "港澳台",
                "天才衝衝衝": "港澳台", "天才冲冲冲": "港澳台", "有線新聞臺": "港澳台", "有线新闻台": "港澳台",
                "博斯": "港澳台", "龍華": "港澳台", "龙华": "港澳台", "ELEVEN": "港澳台", "eleven": "港澳台",
                "有線": "港澳台", "有线": "港澳台", "無綫": "港澳台", "无线": "港澳台", "全民最大黨": "港澳台",
                "全民最大党": "港澳台", "澳視澳門": "港澳台",
                "澳视澳门": "港澳台", "澳視綜藝": "港澳台", "澳视综艺": "港澳台", "澳視葡文": "港澳台",
                "澳视葡文": "港澳台", "澳門MACAU": "港澳台", "澳门MACAU": "港澳台", "澳門蓮花": "港澳台",
                "澳门莲花": "港澳台", "澳門衛視": "港澳台", "澳门卫视": "港澳台", "澳門資訊": "港澳台",
                "澳门资讯": "港澳台", "115新天地民俗臺": "港澳台", "115新天地民俗台": "港澳台", "AXN": "港澳台",
                "CHANNEL [V]": "港澳台", "CMusic": "港澳台", "DISCOVERY Channel": "港澳台",
                "DISCOVERY HD WORLD": "港澳台", "EYE TV戲劇": "港澳台", "EYE TV戏剧": "港澳台", "EYE TV旅遊": "港澳台",
                "EYE TV旅游": "港澳台", "Eleven Sports1": "港澳台", "Eleven Sports2": "港澳台",
                "Food Network(TW)": "港澳台", "Hollywood": "港澳台", "LINE TV 網路電視": "港澳台",
                "LINE TV 网络电视": "港澳台", "Love Nature": "港澳台", "MOMO綜合臺": "港澳台", "MOMO综合台": "港澳台",
                "MOMO購物1臺": "港澳台", "MOMO购物1台": "港澳台", "MOMO購物2臺": "港澳台", "MOMO购物2台": "港澳台",
                "Next TV": "港澳台", "PET CLUB TV": "港澳台", "ROCK Entertainment": "港澳台", "ROCK Extreme": "港澳台",
                "TVBS FHD": "港澳台", "TVBS HD": "港澳台", "Taiwan Plus": "港澳台", "UDN TV": "港澳台", "Z": "港澳台",
                "三立INEWS FHD": "港澳台", "三立INEWS HD": "港澳台", "三立國際": "港澳台", "三立国际": "港澳台",
                "三立戲劇": "港澳台", "三立戏剧": "港澳台", "三立新聞": "港澳台", "三立新闻": "港澳台",
                "三立綜合": "港澳台", "三立综合": "港澳台", "三立臺灣臺": "港澳台", "三立台湾台": "港澳台",
                "三立都會": "港澳台", "三立都会": "港澳台", "中天亞洲": "港澳台", "中天亚洲": "港澳台",
                "中天新聞": "港澳台", "中天新闻": "港澳台", "中視HD": "港澳台", "中视HD": "港澳台",
                "中視新聞": "港澳台", "中视新闻": "港澳台", "中視新聞臺": "港澳台", "中视新闻台": "港澳台",
                "中視經典": "港澳台", "中视经典": "港澳台", "亞洲旅遊臺": "港澳台", "亚洲旅游台": "港澳台",
                "人間衛視": "港澳台", "人间卫视": "港澳台", "信吉電視": "港澳台", "信吉电视": "港澳台",
                "信大電視": "港澳台", "信大电视": "港澳台", "八大綜合": "港澳台", "八大综合": "港澳台",
                "創世電視": "港澳台", "创世电视": "港澳台", "博斯網球": "港澳台", "博斯网球": "港澳台",
                "博斯運動": "港澳台", "博斯运动": "港澳台", "博斯高球": "港澳台", "博斯魅力": "港澳台",
                "唯心電視": "港澳台", "唯心电视": "港澳台", "國家地理頻道": "港澳台", "国家地理频道": "港澳台",
                "國會頻道1": "港澳台", "国会频道1": "港澳台", "大愛": "港澳台", "大爱": "港澳台", "大愛2": "港澳台",
                "大爱2": "港澳台", "大立電視臺": "港澳台", "大立电视台": "港澳台", "好萊塢電影": "港澳台",
                "好莱坞电影": "港澳台", "好訊息": "港澳台", "好讯息": "港澳台", "好訊息 2": "港澳台",
                "好讯息 2": "港澳台", "寰宇新聞": "港澳台", "寰宇新闻": "港澳台", "星衛HD電影": "港澳台",
                "星卫HD电影": "港澳台", "東森幼幼": "港澳台", "东森幼幼": "港澳台", "東森戲劇": "港澳台",
                "东森戏剧": "港澳台", "東森新聞": "港澳台", "东森新闻": "港澳台", "東森新聞臺": "港澳台",
                "东森新闻台": "港澳台", "東森洋片": "港澳台", "东森洋片": "港澳台", "東森綜合": "港澳台",
                "东森综合": "港澳台", "東森美洲": "港澳台", "东森美洲": "港澳台", "東森衛視": "港澳台",
                "东森卫视": "港澳台", "東森財經": "港澳台", "东森财经": "港澳台", "東森財經新聞": "港澳台",
                "东森财经新闻": "港澳台", "東森超視": "港澳台", "东森超视": "港澳台", "東森電影": "港澳台",
                "东森电影": "港澳台", "東風37": "港澳台", "东风37": "港澳台", "民視": "港澳台", "民视": "港澳台",
                "民視新聞": "港澳台", "民视新闻": "港澳台", "民視新聞 HD": "港澳台", "民视新闻 HD": "港澳台",
                "民視臺灣臺": "港澳台", "民视台湾台": "港澳台", "生命電視": "港澳台", "生命电视": "港澳台",
                "番薯電視": "港澳台", "番薯电视": "港澳台", "經典電影臺": "港澳台", "经典电影台": "港澳台",
                "緯來日本": "港澳台", "纬来日本": "港澳台", "緯來綜合": "港澳台", "纬来综合": "港澳台",
                "緯來育樂": "港澳台", "纬来育乐": "港澳台", "美亞電影臺": "港澳台", "美亚电影台": "港澳台",
                "美食星球": "港澳台", "臺視新聞": "港澳台", "台视新闻": "港澳台", "臺視新聞臺": "港澳台",
                "台视新闻台": "港澳台", "臺視綜合": "港澳台", "台视综合": "港澳台", "華視": "港澳台", "华视": "港澳台",
                "華視新聞": "港澳台", "华视新闻": "港澳台", "華視新聞資訊": "港澳台", "华视新闻资讯": "港澳台",
                "衛視電影": "港澳台", "卫视电影": "港澳台", "鏡新聞": "港澳台", "镜新闻": "港澳台",
                "靖天卡通": "港澳台", "靖天國際": "港澳台", "靖天国际": "港澳台", "龍祥電影": "港澳台",
                "龙祥电影": "港澳台", "龍華偶像": "港澳台", "龙华偶像": "港澳台", "龍華戲劇": "港澳台",
                "龙华戏剧": "港澳台", "龍華洋片": "港澳台", "龙华洋片": "港澳台", "美國宇航局": "美利坚合众国",
                "美国宇航局": "美利坚合众国", "美國購物": "美利坚合众国",
                "美国购物": "美利坚合众国", "FOX 體育新聞": "体育", "FOX 体育新闻": "体育", "美國歷史": "美利坚合众国",
                "美国历史": "美利坚合众国", "紅牛運動": "体育", "红牛运动": "体育", "美國1": "美利坚合众国",
                "美国1": "美利坚合众国", "美國之音": "美利坚合众国", "美国之音": "美利坚合众国", "redbull tv": "体育",
                "普洱科教": "电视台", "州科教": "电视台", "經濟科教": "电视台", "经济科教": "电视台",
                "長城精品": "纪录片", "长城精品": "纪录片", "綿陽科技": "电视台", "绵阳科技": "电视台",
                " Fox Sports Racing": "体育", "2016 EURO 2": "体育", "A BOLA TV 1 PT": "体育", "A1 Sports": "体育",
                "ASTRO Arena 2": "体育", "Abu Dhabi Sport 2 UAE": "体育", "Abu Dhabi Sports 1": "体育",
                "Abu Dhabi Sports 2": "体育", "Abu Dhabi Sports 5": "体育", "All Sports": "体育",
                "All Sports TV": "体育", "Arryadia TV": "体育", "Astro Supersports 1": "体育",
                "Astro Supersports 2": "体育",
                "Astro Supersports 3": "体育", "Astro Supersports 4": "体育", "Astro Supersports 5": "体育",
                "BAHRAIN_SPORTS": "体育", "BEIN SPORT 1 HD ": "体育", "BEIN SPORT 2 HD ": "体育",
                "BEIN SPORT 5 HD ": "体育", "BEIN SPORT Ar10": "体育", "BESTV超級體育": "体育", "BESTV超级体育": "体育",
                "BT Sport 1": "体育", "BT Sport 2": "体育", "BT Sport 3": "体育", "BT Sport 4": "体育",
                "BT Sport ESPN": "体育", "BT Sports 2 HD": "体育", "Bally Sports": "体育", "Band Sports": "体育",
                "BeIN Sports 1": "体育", "BeIN Sports 2": "体育", "BeIN Sports3 EN": "体育",
                "Bein Sport 3 France": "体育", "Bein Sport HD 1 Qatar (Arabic)": "体育",
                "Bein Sports 3 France (English)": "体育", "Bein Sports 5 France (English)": "体育",
                "Bein Sports HD": "体育", "Bein Sports HD 1 France": "体育", "Brodilo TV HD": "体育", "CCTV16": "体育",
                "CCTV5": "体育", "CCTV5+": "体育", "CCTV央視檯球": "体育", "CCTV央视台球": "体育",
                "CCTV風雲足球": "体育", "CCTV风云足球": "体育", "CCTV高爾夫網球": "体育", "CCTV高尔夫网球": "体育",
                "Canal 4 (El Salvador)": "体育", "Canal Esport3": "体育", "Claro Sports": "体育", "DD Sports": "体育",
                "Diema Sport 1-2": "体育", "Dubai Racing 2 TV": "体育",
                "Dubai Racing TV": "体育", "Dubai Sport 1": "体育", "ESPN 3": "体育", "ESPN NEWS": "体育",
                "ESPN U": "体育", "EURO SPORT 1 HD": "体育", "EUROSPORT 1 Portugal": "体育",
                "EuroSport 2 HD UK": "体育", "EuroSport Deutschland": "体育", "Eurosport 2": "体育",
                "Eurosport2 HD UK": "体育", "Eurosports 1 HD UK": "体育", "FOX Sports 2": "体育",
                "FOX Sports 3": "体育", "FS1": "体育", "Fight Box HD": "体育", "Fight Sports": "体育",
                "FightBox TV": "体育", "Fox Sports 1": "体育", "Fox Sports 1 USA": "体育", "Fox Sports Turk": "体育",
                "GOLF": "体育", "Goan_TV": "体育", "Golf Channel": "体育", "HTV Thể thao": "体育",
                "HUB Sports2": "体育", "HUBPREMIER EFL 2": "体育", "IB Sports TV": "体育", "ITV": "体育",
                "ITV 4 UK": "体育", "J SPORTS 1": "体育", "J SPORTS 2": "体育", "J SPORTS 4": "体育",
                "KBSN LIFE": "体育", "KSA Sports": "体育", "Kompas TV": "体育", "Equipe": "体育",
                "Liga De Campeones 2": "体育", "MBC Sport 1": "体育", "MCOT HD": "体育", "MLB": "体育",
                "MOTORVISION HD": "体育", "MUTV": "体育", "Marca TV": "体育", "Meridiano Televisión": "体育",
                "Milan Channel": "体育", "Mitele Deportes": "体育", "Motorsz TV": "体育", "Movistar Deportes": "体育",
                "N SPORT+": "体育", "NBA HD": "体育", "NBA Premium": "体育", "NBA TV": "体育", "NBC Sport": "体育",
                "NBCSN": "体育", "NBT HD": "体育", "NESN": "体育", "NEWTV武搏世界": "体育", "NEWTV精品體育": "体育",
                "NEWTV精品体育": "体育", "NEWTV超級體育": "体育", "NEWTV超级体育": "体育", "NFL": "体育",
                "NFL REDZONE": "体育", "NOVA SPORT": "体育", "NPO Sport": "体育", "NTV CAMBODIA": "体育",
                "Nautical Channel Russia": "体育", "ORANGE SPORT": "体育", "OSN Fight HD UAE": "体育",
                "PFC O Canal Do Futebol": "体育", "PPV 1 (LIVE EVENT)": "体育", "PPV 3": "体育", "PX TV": "体育",
                "Pac12": "体育", "Persiana Game & Tech": "体育", "Pocker Central": "体育", "Polsat Sport PL": "体育",
                "Premier Sport": "体育", "Premier Sports": "体育", "Premium Calcio Italia": "体育",
                "Pro Wrestling Channel": "体育", "RDS 2 HD": "体育", "RMC Sport France": "体育",
                "RTL Nitro Deutschland": "体育", "RTSH Sport HD": "体育", "Rai Sport 2 SD": "体育",
                "Real Madrid TV": "体育", "Red Bull TV": "体育", "Russian Extreme": "体育", "S SPORT TV": "体育",
                "SBS Sports": "体育", "SCTV15 SPORT": "体育", "SETANTA SPORTS+": "体育", "SKY Bundesliga 1": "体育",
                "SKY Sports Arena": "体育", "SKY Sports Football": "体育", "SKY Sports MIX": "体育",
                "SKYNET SPORTS HD": "体育", "SPORT 5 LIVE": "体育", "SPORT 5+ LIVE": "体育", "SPORT MAX": "体育",
                "SPORT TV 3 PT": "体育", "SPOTV 1": "体育", "SPOTV2": "体育", "STAR SPORTS SELECT 1": "体育",
                "Samurai Fighting TV": "体育", "Setanta": "体育", "Setanta Sports HD": "体育", "Sky Calcio": "体育",
                "Sky Sport 24 HD Italia": "体育", "Sky Sport F1 HD Italia": "体育", "Sky Sports Action": "体育",
                "Sky Sports F1": "体育", "Sky Sports Golf": "体育", "Sky Sports Main Event": "体育",
                "Sky Sports NFL": "体育", "Sky Sports News HQ": "体育", "Sky Sports Premier League": "体育",
                "Sky Sports Racing": "体育", "Sony Ten2": "体育", "Sony Ten3": "体育", "SporTV 1": "体育",
                "Sport - San Marino RTV": "体育", "Sport 1": "体育", "Sport 1 HD": "体育",
                "Sport 1 Select HD Netherlands": "体育", "Sport Italia": "体育", "Sport Klub 2 HD Srbija": "体育",
                "Sport Klub 2 Srbija": "体育", "Sport Klub 3 HD Srbija": "体育", "Sport Plus": "体育",
                "Sport TV 1": "体育", "Sport TV 2": "体育", "Sport TV 3": "体育", "Sport TV 4": "体育",
                "Sport TV1": "体育", "Sport TV3": "体育", "Sporting TV": "体育", "Sports Network": "体育",
                "SportsNet 1": "体育", "Sportsnet West": "体育", "Stadium4 Thai": "体育", "Star Sport 1": "体育",
                "Sukan RTM": "体育", "Super Sport 3 HD": "体育", "SuperSport Cricket": "体育", "SuperTennis TV": "体育",
                "Supersport Football": "体育", "TDP Teledeporte": "体育", "TF1 HD": "体育", "TFX": "体育",
                "TIDE SPORTS": "体育", "TSN 1": "体育", "TSN 2": "体育", "TSN 3": "体育", "TSN 4": "体育",
                "TV 2 Sport": "体育", "TV 2 Sportskanalen": "体育", "TV Globo": "体育", "TV TOUR": "体育",
                "TV Urbana": "体育", "TVA SPORT": "体育", "TVCG 2": "体育", "TVMax": "体育",
                "TVU Esporte Brasil": "体育", "Tele Rebelde": "体育", "Telemetro canal 13, Panamá": "体育",
                "Telemundo": "体育", "Telemundo 48 El Paso": "体育", "Telenord": "体育", "Tempo TV": "体育",
                "Tennis": "体育", "Tivibu Spor Türkiye": "体育", "Trace Sport Stars": "体育", "Trace Sports": "体育",
                "Tring Sport 2 Albania": "体育", "Tsn Livigno": "体育", "Tv Luna Sport": "体育", "TyC Sports": "体育",
                "Türkmen Sport": "体育", "UFC TV": "体育", "Unbeaten Esports": "体育", "Univisión TDN Mexico": "体育",
                "Usee sports": "体育", "ViaSat Sport Россия": "体育", "Viasat Motor Sweden": "体育",
                "Viasat Sport HD Sweden": "体育", "WWE HD": "体育", "WWE Network": "体育", "Win Sports": "体育",
                "World Fishing Network": "体育", "XPER TV Costa Rica": "体育", "XSport Ukraine": "体育",
                "Yas Sports": "体育", "a Spor TUR": "体育", "adsport 1": "体育", "adsport 2": "体育",
                "beIN SPORTS France": "体育", "beIN Sports 2 ID": "体育", "beIN Sports 3 ID": "体育",
                "beIN Sports MENA": "体育", "iDMAN TV Türkiye": "体育", "İdman Azərbaycan TV": "体育",
                "МАТЧ! БОЕЦ": "体育", "Матч ТВ": "体育", "Матч!": "体育", "НТВ Плюс Теннис Россия": "体育",
                "Перший Avtomobilniy": "体育", "Спорт Россия": "体育", "Телеканал Старт": "体育",
                "Телеканал Футбол 1": "体育", "五星體育": "体育", "五星体育": "体育", "先鋒乒羽": "体育",
                "先锋乒羽": "体育", "勁爆體育": "体育", "劲爆体育": "体育", "北京冬奧紀實": "体育",
                "北京冬奥纪实": "体育", "北京體育": "体育", "北京体育": "体育", "北京體育休閒": "体育",
                "北京体育休闲": "体育", "噠啵賽事": "体育", "哒啵赛事": "体育", "四海釣魚": "体育", "四海钓鱼": "体育",
                "天元圍棋": "体育", "天元围棋": "体育", "天津體育": "体育", "天津体育": "体育", "山東體育": "体育",
                "山东体育": "体育", "廣東體育": "体育", "广东体育": "体育", "快樂垂釣": "体育", "快乐垂钓": "体育",
                "武漢文體": "体育", "武汉文体": "体育", "武術世界": "体育", "武术世界": "体育", "江蘇體育休閒": "体育",
                "江苏体育休闲": "体育", "洛陽新聞綜合": "体育", "洛阳新闻综合": "体育", "精彩體育": "体育",
                "精彩体育": "体育", "遊戲風雲": "游戏频道", "游戏风云": "游戏频道", "運動健身": "体育",
                "运动健身": "体育", "陝西體育休閒": "体育", "陕西体育休闲": "体育", "電競天堂": "体育",
                "电竞天堂": "体育", "體育賽事": "体育", "体育赛事": "体育", "高爾夫": "体育", "高尔夫": "体育",
                "魅力足球": "体育", "FOXNews": "美利坚合众国", "Ion Plus": "美利坚合众国", "ION Plus": "美利坚合众国",
                "美國中文": "美利坚合众国", "美国中文": "美利坚合众国", "美國狗狗寵物": "美利坚合众国",
                "美国狗狗宠物": "美利坚合众国", "BlazeTV": "美利坚合众国", "Seattle Channel": "美利坚合众国",
                "美國新聞": "美利坚合众国", "美国新闻": "美利坚合众国", "CBS News": "美利坚合众国",
                "TBS": "美利坚合众国", "NBC": "美利坚合众国", "Hallmark Movies": "美利坚合众国",
                "Disney XD": "美利坚合众国", "AMC US": "美利坚合众国", "HGTV": "美利坚合众国", "tru TV": "美利坚合众国",
                "Fox 5 WNYW": "美利坚合众国", "ABC HD": "美利坚合众国", "My9NJ": "美利坚合众国",
                "Live Well Network": "美利坚合众国", "Gulli": "美利坚合众国", "Tiji TV": "美利坚合众国",
                "WPIX-TV": "美利坚合众国", "MOTORTREND": "美利坚合众国", "BBC America": "美利坚合众国",
                "THIRTEEN": "美利坚合众国", "WLIW21": "美利坚合众国", "NJTV": "美利坚合众国", "MeTV": "美利坚合众国",
                "SBN": "美利坚合众国", "WMBC Digital Television": "美利坚合众国", "Univision": "美利坚合众国",
                "nba": "美利坚合众国", "NBA": "美利坚合众国", "fox news": "美利坚合众国", "FOX News": "美利坚合众国",
                ".sci-fi": "美利坚合众国", "UniMÁS": "美利坚合众国", "Cartoons_90": "美利坚合众国",
                "Cartoons Short": "美利坚合众国", "Cartoons Big": "美利坚合众国", "CineMan": "美利坚合众国",
                "USA": "美利坚合众国", "BCU Кинозал Premiere": "美利坚合众国", "TNT": "美利坚合众国",
                "NBC NEWS": "美利坚合众国", "SKY SPORT": "体育", "Auto Motor Sport": "体育", "sky sport": "体育",
                "sky Sport": "体育", "BT SPORT": "体育", "sportv": "体育", "fight sport": "体育", "Sportitalia": "体育",
                "sportitalia": "体育", "elta sport": "体育", "Sport 5": "体育", "claro sport": "体育", "xsport": "体育",
                "sporting": "体育", "TV3 sport": "体育", "Trace Sport": "体育", "SPORT 1": "体育", "sport 3": "体育",
                "sport 4k": "体育", "edgesport": "体育", "sport club": "体育", "sport tv": "体育", "j sport": "体育",
                "viasat sport": "体育", "sport 5": "体育", "QAZsport_live": "体育", "SPORT 5": "体育",
                "SPORT 2": "体育", "Alfa Sport": "体育", "tring sport": "体育", "wwe": "体育", "WWE": "体育",
                "Sportv": "体育", "diema sport": "体育", "Edge Sport": "体育", "supersport": "体育", "sport ru": "体育",
                "Sport+": "体育", "Esport3": "体育", "Sport En France": "体育", "sport en": "体育", "sports": "体育",
                "Pluto TV SPORT": "体育", "NBC News": "体育", "ssc sport": "体育", "SporTV": "体育",
                "bein sport": "体育", "Sports": "体育", "SPORT TV": "体育", "FR_RMC_Sport": "体育", "EDGEsport": "体育",
                "Box Nation": "体育", "Brodilo TV": "体育", "CBC Sport": "体育", "cbc Sport": "体育", "檯球": "体育",
                "台球": "体育", "央視撞球": "体育", "央视台球": "体育", "風雲足球": "体育", "风云足球": "体育",
                "高爾夫網球": "体育", "高尔夫网球": "体育", "CDN Deportes": "体育",
                "CDO PREMIUM SANTIAGO CHILE LATAM": "体育", "SPORTS": "体育", "k+ sport": "体育", "digi sport": "体育",
                "Eurosport": "体育", "Sport 3": "体育", "cdo premium": "体育", "CSI Web Tv": "体育",
                "Campo Televisión": "体育", "Canal 4": "体育", "canal 4": "体育", "Canal+ Sport": "体育",
                "canal+ sport": "体育", "Chelsea TV": "体育", "chelsea tv": "体育", "DAZN F1": "体育",
                "dazn f1": "体育", "DIGISPORT": "体育", "DMC Sport": "体育", "NFL NETWORK": "美利坚合众国",
                "WWE NETWORK": "体育", "A&E": "美利坚合众国", "Dazn 1": "体育", "AMC": "美利坚合众国",
                "BBC AMERICA": "美利坚合众国", "BET": "美利坚合众国", "dazn 1": "体育", "BRAVO": "美利坚合众国",
                "USA NETWORK": "美利坚合众国", "CNBC": "美利坚合众国", "dazn 01": "体育", "NHL Network": "美利坚合众国",
                "5USA": "美利坚合众国", "CBS SPORTS": "体育", "dazn 2": "体育", "FOX SPORTS": "体育",
                "MSG US": "美利坚合众国", "MSG 2 US": "美利坚合众国", "dazn 3": "体育", "dazn 4": "体育",
                "deportv": "体育", "DeporTV": "体育", "Diema Sport": "体育", "Dubai Racing": "体育",
                "dubai racing": "体育", "Dubai Sport": "体育", "dubai sport": "体育", "EDGE Sport": "体育",
                "edge sport": "体育", "EURO SPORT": "体育", "edge sportᴴᴰ": "体育", "ESL Gaming tv": "体育",
                "gaming tv": "体育", "ESPN": "体育", "espn": "体育", "eurosport": "体育", "EUROSPORT": "体育",
                "Equipe 21": "体育", "equipe 21": "体育", "Esports Max": "体育", "esports max": "体育",
                "EuroSport": "体育", "FOX Deportes": "体育", "fox deportes": "体育", "FOX SP506": "体育",
                "FOX 5 Atlanta GA": "体育", "WAGA-TV": "体育", "fox sport": "体育", "Fast&FunBox": "体育",
                "funbox": "体育", "fast&fun box": "体育", "Fenerbahce TV": "体育", "fenerbahçe tv": "体育",
                "Ion Television": "美利坚合众国", "NYCTV Life": "美利坚合众国", "TENNIS HD": "美利坚合众国",
                "CINEMAXX MORE MAXX": "美利坚合众国", "CINEMAX THRILLERMAX": "美利坚合众国", "fight box": "体育",
                "Fight Box": "体育", "Fight Channel": "体育", "channel fight": "体育", "fightbox": "体育",
                "FightBox": "体育", "Football Thai": "体育", "Football UK": "体育", "CINEMAX OUTER MAX": "美利坚合众国",
                "CINEMAX MOVIEMAX": "美利坚合众国", "on football": "体育", "CINEMAX ACTION MAX": "美利坚合众国",
                "MTV Classic": "美利坚合众国", "football focus": "体育", "football fhd": "体育", "gol tv": "体育",
                "GOLTV": "体育", "goltv": "体育", "Game Show Network": "体育", "Gameplay Roblox": "体育",
                "gameplay: roblox": "体育", "roblox": "体育", "Gamer.tv": "体育", "Espn News": "美利坚合众国",
                "ESPN 2": "美利坚合众国", "ESPN USA": "美利坚合众国", "Discovery Channel": "美利坚合众国",
                "MAVTV": "美利坚合众国", "布蘭奇電視": "美利坚合众国", "布兰奇电视": "美利坚合众国",
                "美國l": "美利坚合众国", "美国l": "美利坚合众国", "美國中央臺": "美利坚合众国",
                "美国中央台": "美利坚合众国", "IN: Harvest TV USA": "美利坚合众国",
                "LeSEA Broadcasting Network": "美利坚合众国", "US: USA Network": "美利坚合众国",
                "CBS New York": "美利坚合众国", "ABC News": "美利坚合众国", "AFG: ATN USA": "美利坚合众国",
                "usa fight network": "美利坚合众国", "E! Entertaiment USA": "美利坚合众国", "USA Today": "美利坚合众国",
                "usa espn": "美利坚合众国", "UK: 5 USA": "美利坚合众国", "CMC-USA": "美利坚合众国",
                "usa disney": "美利坚合众国", "usa network": "美利坚合众国", "usa ufc": "美利坚合众国",
                "usa wwe": "体育", "usa mtv": "美利坚合众国", "usa crime": "美利坚合众国", "usa cnbc": "美利坚合众国",
                "GoUSA TV": "美利坚合众国", "Harvest TV USA": "美利坚合众国", "jltv usa": "美利坚合众国",
                "Best Movies HD (USA)": "美利坚合众国", "usa news": "美利坚合众国", "Go USA": "美利坚合众国",
                "usa american heroes": "美利坚合众国", "usa tcm": "美利坚合众国",
                "lesea broadcasting network (usa)": "美利坚合众国", "usa c-span": "美利坚合众国",
                "usa hbo": "美利坚合众国", "cnn usa": "美利坚合众国", "CNN": "美利坚合众国", "usa": "美利坚合众国",
                "american": "美利坚合众国", "Gunma TV": "日本台", "American": "美利坚合众国", "cnn": "美利坚合众国",
                "CNNj": "日本台", "FUJI TV": "日本台", "fuji tv": "日本台", "Golf Network": "体育",
                "golazo network": "体育", "TOKYO MX": "日本台", "Tokyo MX": "日本台", "tokyo mx": "日本台",
                "Weather News": "日本台", "weathernews": "日本台",
                "WeatherNews": "日本台", "NHK": "日本台", "TV Tokyo": "日本台", "Star 1": "日本台",
                "Star 2": "日本台", "Nippon TV": "日本台", "MBS": "日本台", "Animax": "日本台", "QVC Japan": "日本台",
                "ANIMAX": "日本台", "animax": "日本台", "nhk": "日本台", "qvc - japan": "日本台", "qvc japan": "日本台",
                "朝日": "日本台", "aniplus": "日本台", "JSTV": "日本台", "directv sport": "体育",
                "WeatherSpy": "日本台", "dTV(Japan)": "日本台", "A BOLA TV": "体育", "A-sport": "体育",
                "astro supersport": "体育", "Automoto": "体育", "BEIN SPORT": "体育", "bein sports": "体育",
                "ziggo sport": "体育", "sharjjah sport": "体育", "mysports 1": "体育", "AS TV Spain": "体育",
                "Arena Sport": "体育", "arena sport": "体育", "Argentina - TyC": "体育", "Astro Supersports": "体育",
                "NHK BS": "日本台", "nhk world": "国际", "STAR CHANNEL": "日本台", "star channe": "日本台",
                "Samurai Fighting": "日本台", "samurai x": "日本台", "euro star": "日本台", "star tv": "日本台",
                "tv asahi": "日本台", "U-NEXT": "日本台", "Degrassi The Next Generation": "日本台",
                "tv tokyo": "日本台", "Aniplus": "日本台", "BS TBS": "日本台", "Jupiter Shop Channel": "日本台",
                "KIDS STATION": "日本台", "Kansai TV": "日本台", "kanshi tv": "日本台", "Lala TV": "日本台",
                "lana tv": "日本台", "MBS JAPAN": "日本台", "Mondo TV": "日本台", "MONDO TV": "日本台",
                "Fuji TV": "日本台", "TV Asahi": "日本台", "テレビ東京": "日本台", "テレビ东京": "日本台",
                "BS Fuji": "日本台", "bs-tbs": "日本台", "BS Asahi": "日本台", "BS Tokyo": "日本台",
                "WOWOW Prime": "日本台", "WOWOWO 電影": "日本台", "WOWOWO 电影": "日本台", "雲遊日本": "日本台",
                "云游日本": "日本台", "日本女子摔角": "日本台", "TBS NEWS": "日本台", "日本テレビ": "日本台",
                "WOWOWライブ": "日本台", "WOWOWプライム": "日本台", "J Sports": "体育", "Animal": "自然", "日本購物": "日本台",
                "日本购物": "日本台", "Disney Channel Japan": "日本台", "JAPAN3": "日本台", "JAPAN5": "日本台",
                "JAPAN6": "日本台", "JAPAN7": "日本台", "JAPAN8": "日本台", "JAPAN9": "日本台", "日本News24": "日本台",
                "日本映畫": "日本台", "日本映画": "日本台", "GSTV": "日本台", "WOWOWシネマ": "日本台",
                "BS12 TwellV": "日本台", "BS朝日": "日本台", "超級體育": "体育", "超级体育": "体育", "BT Sport": "体育",
                "bt sport": "体育", "スターチャンネル": "日本台", "BSアニマックス": "日本台", "日-J Sports": "体育",
                "釣りビジョン": "日本台", "钓りビジョン": "日本台", "フジテレビ": "日本台", "東映チャンネル": "日本台",
                "东映チャンネル": "日本台", "チャンネルNECO": "日本台", "ムービープラス": "日本台", "スカイA": "日本台", "GAORA": "日本台",
                "日テレジータス": "日本台", "ゴルフネットワーク": "日本台", "時代劇専門チャンネル": "日本台", "时代剧専门チャンネル": "日本台",
                "ファミリー劇場": "日本台", "ファミリー剧场": "日本台", "ホームドラマチャンネル": "日本台", "チャンネル銀河": "日本台",
                "チャンネル银河": "日本台", "スーパー!ドラマTV": "日本台", "LaLaTV": "日本台", "Music ON TV": "日本台",
                "歌謡ポップスチャンネル": "日本台", "歌谣ポップスチャンネル": "日本台", "キッズステーション": "日本台", "日テレNEWS24": "日本台",
                "囲碁・將棋チャンネル": "日本台", "囲碁・将棋チャンネル": "日本台", "Shop Channel": "日本台", "MX Live": "日本台",
                "ウェザーニュース": "日本台", "群馬テレビ": "日本台", "群马テレビ": "日本台", "漫步日本": "日本台",
                "中國氣象": "纪录片", "中国气象": "纪录片",
                "衛視": "卫视", "卫视": "卫视", "CGTN": "央视", "環球電視": "央视", "环球电视": "央视", "華數": "华数",
                "华数": "华数", "wasu.tv": "华数", "CIBN": "CIBN", "/cibn": "CIBN", "NewTv": "NewTv", "NEWTV": "NewTV",
                "/newtv": "NewTV", "百視通": "百视通", "百视通": "百视通", "百事通": "百视通", "BesTV": "百视通",
                "NewTV": "NewTV", "Cinevault 80": "美利坚合众国", "BESTV": "百视通", "BestTv": "百视通",
                "/bestv": "百视通", ".bestv": "百视通", "新聞": "电视台", "新闻": "电视台", "體育": "体育",
                "体育": "体育", "動漫": "动漫", "动漫": "动漫", "NASA": "科技", "豆瓣": "影视", "電影": "影视",
                "电影": "影视", "動畫": "动画", "动画": "动画", "運動": "体育", "运动": "体育", "卡通": "卡通",
                "影院": "影视", "足球": "体育", "劇場": "剧场", "剧场": "剧场", "東方": "", "东方": "",
                "紀實": "纪录片", "纪实": "纪录片", "電競": "游戏频道", "电竞": "游戏频道", "教育": "教育",
                "自然": "自然", "動物": "自然", "动物": "自然", "NATURE": "自然", "成龍": "明星", "成龙": "明星",
                "李連杰": "明星", "李连杰": "明星", "周星馳": "明星", "周星驰": "明星", "吳孟達": "明星",
                "吴孟达": "明星", "劉德華": "明星", "刘德华": "明星", "周潤發": "明星", "周润发": "明星",
                "洪金寶": "明星", "洪金宝": "明星", "黃渤": "明星", "黄渤": "明星", "林正英": "明星", "七龍珠": "动漫",
                "七龙珠": "动漫", "海綿寶寶": "动漫", "海绵宝宝": "动漫", "貓和老鼠": "动漫", "猫和老鼠": "动漫",
                "網球王子": "动漫", "网球王子": "动漫", "蠟筆小新": "动漫", "蜡笔小新": "动漫", "海賊王": "动漫",
                "海贼王": "动漫", "中華小當家": "动漫", "中华小当家": "动漫", "四驅兄弟": "动漫", "四驱兄弟": "动漫",
                "哆啦A夢": "动漫", "哆啦A梦": "动漫", "櫻桃小丸子": "动漫", "樱桃小丸子": "动漫", "柯南": "动漫",
                "犬夜叉": "动漫", "亂馬": "动漫", "乱马": "动漫", "童年": "", "高達": "动漫", "高达": "动漫",
                "守護甜心": "动漫", "守护甜心": "动漫", "開心超人": "动漫", "开心超人": "动漫", "開心寶貝": "动漫",
                "开心宝贝": "动漫", "百變小櫻": "动漫", "百变小樱": "动漫", "咱們裸熊": "动漫", "咱们裸熊": "动漫",
                "遊戲王": "动漫", "游戏王": "动漫", "三國演義": "剧场", "三国演义": "剧场", "連續劇": "剧场",
                "连续剧": "剧场", "音樂": "音乐", "音乐": "音乐", "綜合": "电视台", "综合": "电视台", "財經": "电视台",
                "财经": "电视台", "經濟": "电视台", "经济": "电视台", "美食": "美食", "資訊": "电视台",
                "资讯": "电视台", "旅遊": "电视台", "旅游": "电视台", "Fashion4K": "时尚", "黑莓": "其他",
                "綜藝": "电视台", "综艺": "电视台", "都市": "电视台", "看天下": "其他", "咪咕": "咪咕", "諜戰": "剧场",
                "谍战": "剧场", "華語": "其他", "华语": "其他", "影視": "影视", "影视": "影视", "科教": "电视台",
                "生活": "电视台", "discovery": "探索发现", "娛樂": "其他", "娱乐": "其他", "電視": "电视台",
                "电视": "电视台", "紀錄": "纪录片", "纪录": "纪录片", "外語": "外语", "外语": "外语", "車迷": "时尚",
                "车迷": "时尚", "留學": "留学", "留学": "留学", "新聞頻道": "电视台", "新闻频道": "电视台",
                "靚裝": "时尚", "靓装": "时尚", "戲曲": "戏曲", "戏曲": "戏曲", "電視臺": "电视台", "电视台": "电视台",
                "綜合頻道": "电视台", "综合频道": "电视台", "法制": "电视台", "數碼": "电视台", "数码": "电视台",
                "汽車": "时尚", "汽车": "时尚", "軍旅": "影视", "军旅": "影视", "古裝": "影视", "古装": "影视",
                "喜劇": "影视", "喜剧": "影视", "驚悚": "影视", "惊悚": "影视", "懸疑": "影视", "悬疑": "影视",
                "科幻": "影视", "全球大片": "影视", "詠春": "影视", "咏春": "影视", "黑幫": "影视", "黑帮": "影视",
                "古墓": "影视", "警匪": "影视", "少兒": "少儿", "少儿": "少儿", "課堂": "教育", "课堂": "教育",
                "政務": "电视台", "政务": "电视台", "民生": "电视台", "農村": "电视台", "农村": "电视台",
                "人文": "电视台", "幸福彩": "电视台", "新視覺": "科技", "新视觉": "科技", "金色頻道": "其他",
                "金色频道": "其他", "新華英文": "国际", "新华英文": "国际", "垂釣": "体育", "垂钓": "体育",
                "NHK WORLD": "国际", "時代": "其他", "时代": "其他", "休閒": "其他", "休闲": "其他",
                "ANN News FHD": "日本台", "兵器": "兵器", "band news": "日本台", "純享": "纪录片", "纯享": "纪录片",
                "ann_news": "日本台", "SiTV": "其他", "CHC": "影视", "nhk-hd": "国际", "BRTV": "其他",
                "Lifetime": "其他", "nhk hd": "国际", "GINX": "其他", "Rollor": "其他", "Generic": "国际",
                "GlobalTrekker": "其他", "LUXE TV": "其他", "Insight": "国际", "Evenement": "其他",
                "Clarity": "美利坚合众国", "hbo": "美利坚合众国", "TRAVELXP": "其他", "ODISEA": "其他",
                "MUZZIK": "其他", "SKY HIGH": "美利坚合众国", "Liberty": "其他"
                }
        redis_add_map(REDIS_KEY_M3U_WHITELIST, dict)
        m3u_whitlist = dict.copy()
    else:
        m3u_whitlist = dict.copy()
    if not dictRank or len(dictRank) == 0:
        dictRank = {'央视': '1', '港澳台': '3', '卫视': '2', '日本台': '4', '美利坚合众国': '5', '百视通': '7',
                    'NewTV': '8', '国际': '6',
                    'CIBN': '12', '体育': '0', '华数': '10', '动漫': '11', '影视': '27', '明星': '13',
                    '自然': '14',
                    '剧场': '15', '动画': '16', '卡通': '17', '探索发现': '18', '少儿': '20',
                    '戏曲': '21',
                    '教育': '22', '科技': '23', '时尚': '24',
                    '游戏频道': '25', '留学': '26', '纪录片': '19', '电视台': '9', '美食': '28',
                    '音乐': '29', '其他': '30'
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
                          'maxTimeoutTsSeen': '300', 'maxTimeoutTsAlive': '30', 'maxTimeoutTsFree': '300',
                          'maxTimeoutM3u8Free': '300'}


def init_file_name():
    dict = redis_get_map(REDIS_KEY_FILE_NAME)
    if dict:
        global file_name_dict
        file_name_dict.clear()
        file_name_dict = dict.copy()
    else:
        redis_add_map(REDIS_KEY_FILE_NAME, file_name_dict_default)


def init_webdav_m3u():
    dict = redis_get_map(REDIS_KEY_WEBDAV_M3U)
    if dict:
        global redisKeyWebDavM3u
        redisKeyWebDavM3u.clear()
        redisKeyWebDavM3u = dict.copy()
    dict2 = redis_get_map(REDIS_KEY_WEBDAV_M3U_DICT_RAW)
    if dict2:
        global true_webdav_m3u_dict_raw
        true_webdav_m3u_dict_raw.clear()
        true_webdav_m3u_dict_raw = dict2.copy()
    dict3 = redis_get_map(REDIS_KEY_webdav_M3U_TYPE)
    if dict3:
        global redisKeyWebdavM3uType
        redisKeyWebdavM3uType.clear()
        redisKeyWebdavM3uType = dict3.copy()


def init_webdav_m3u_True_Data():
    dict2 = redis_get_map(REDIS_KEY_WEBDAV_M3U_DICT_RAW)
    if dict2:
        global true_webdav_m3u_dict_raw
        true_webdav_m3u_dict_raw.clear()
        true_webdav_m3u_dict_raw = dict2.copy()


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
def getExtraDnsPort3():
    num = init_pass('proxy')
    return jsonify({'button': num})


# 获取IPV6订阅密码
@app.route('/api/getExtraDnsPort2', methods=['GET'])
def getExtraDnsPort2():
    num = init_pass('ipv6')
    return jsonify({'button': num})


# 获取IPV4订阅密码
@app.route('/api/getExtraDnsServer2', methods=['GET'])
def getExtraDnsServer2():
    num = init_pass('ipv4')
    return jsonify({'button': num})


# 获取域名黑名单订阅密码
@app.route('/api/getChinaDnsPort2', methods=['GET'])
def getChinaDnsPort2():
    num = init_pass('blacklist')
    return jsonify({'button': num})


# 获取域名白名单订阅密码
@app.route('/api/getChinaDnsServer2', methods=['GET'])
def getChinaDnsServer2():
    num = init_pass('whitelist')
    return jsonify({'button': num})


# 获取直播源订阅密码
@app.route('/api/getThreadNum2', methods=['GET'])
def getThreadNum2():
    num = init_pass('m3u')
    return jsonify({'button': num})


# 导出加密订阅密码历史记录配置
@app.route('/api/download_json_file14', methods=['GET'])
def download_json_file14():
    return download_json_file_base(REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS,
                                   f"{secret_path}temp_historysubscribepasslist.json"
                                   )


# 删除加密订阅密码历史记录
@app.route('/api/deletewm3u14', methods=['POST'])
def deletewm3u14():
    return dellist(request, REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS)


# 拉取全部加密订阅密码历史记录
@app.route('/api/getall14', methods=['GET'])
def getall14():
    return jsonify(redis_get_map(REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS))


# 加密订阅密码历史记录-导入json配置
@app.route('/api/upload_json_file14', methods=['POST'])
def upload_json_file14():
    return upload_json(request, REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS, f"{secret_path}tmp_data14.json")


# 上传简易DNS黑名单json文件
@app.route('/api/upload_json_file13', methods=['POST'])
def upload_json_file13():
    redis_add(REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG, 1)
    return upload_json(request, REDIS_KEY_DNS_SIMPLE_BLACKLIST, f"{secret_path}tmp_data13.json")


# 上传直播源订阅配置集合文件
@app.route('/api/upload_json_file', methods=['POST'])
def upload_json_file():
    return upload_json(request, REDIS_KEY_M3U_LINK, f"{secret_path}tmp_data.json")


# 上传白名单订阅配置集合文件
@app.route('/api/upload_json_file2', methods=['POST'])
def upload_json_file2():
    return upload_json(request, REDIS_KEY_WHITELIST_LINK, f"{secret_path}tmp_data2.json")


# 上传黑名单订阅配置集合文件
@app.route('/api/upload_json_file3', methods=['POST'])
def upload_json_file3():
    return upload_json(request, REDIS_KEY_BLACKLIST_LINK, f"{secret_path}tmp_data3.json")


# 上传中国ipv4订阅配置集合文件
@app.route('/api/upload_json_file4', methods=['POST'])
def upload_json_file4():
    return upload_json(request, REDIS_KEY_WHITELIST_IPV4_LINK, f"{secret_path}tmp_data4.json")


# 上传中国ipv6订阅配置集合文件
@app.route('/api/upload_json_file5', methods=['POST'])
def upload_json_file5():
    return upload_json(request, REDIS_KEY_WHITELIST_IPV6_LINK, f"{secret_path}tmp_data5.json")


# 上传密码本配置集合文件
@app.route('/api/upload_json_file6', methods=['POST'])
def upload_json_file6():
    return upload_json(request, REDIS_KEY_PASSWORD_LINK, f"{secret_path}tmp_data6.json")


# 上传简易DNS白名单json文件
@app.route('/api/upload_json_file12', methods=['POST'])
def upload_json_file12():
    redis_add(REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG, 1)
    return upload_json(request, REDIS_KEY_DNS_SIMPLE_WHITELIST, f"{secret_path}tmp_data12.json")


# 上传m3u白名单json文件
@app.route('/api/upload_json_file11', methods=['POST'])
def upload_json_file11():
    return upload_json(request, REDIS_KEY_M3U_WHITELIST, f"{secret_path}tmp_data11.json")


# 上传m3u白名单json文件
@app.route('/api/upload_json_file16', methods=['POST'])
def upload_json_file16():
    return upload_json(request, REDIS_KEY_M3U_WHITELIST_RANK, f"{secret_path}tmp_data16.json")


# 上传下载加密上传json文件
@app.route('/api/upload_json_file17', methods=['POST'])
def upload_json_file17():
    return upload_json(request, REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME, f"{secret_path}tmp_data17.json")


# 上传下载解密密json文件
@app.route('/api/upload_json_file18', methods=['POST'])
def upload_json_file18():
    return upload_json(request, REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME, f"{secret_path}tmp_data18.json")


# 上传m3u黑名单json文件
@app.route('/api/upload_json_file15', methods=['POST'])
def upload_json_file15():
    return upload_json(request, REDIS_KEY_M3U_BLACKLIST, f"{secret_path}tmp_data15.json")


# 上传加密订阅重命名json文件
@app.route('/api/upload_json_file19', methods=['POST'])
def upload_json_file19():
    return upload_json(request, REDIS_KEY_FILE_NAME, f"{secret_path}tmp_data19.json")


# 上传订阅密码锁json文件
@app.route('/api/upload_json_file20', methods=['POST'])
def upload_json_file20():
    return upload_json(request, REDIS_KEY_SECRET_PASS_NOW, f"{secret_path}tmp_data20.json")


# 上传gitee同步账号json文件
@app.route('/api/upload_json_file21', methods=['POST'])
def upload_json_file21():
    return upload_json(request, REDIS_KEY_GITEE, f"{secret_path}tmp_data21.json")


# 上传gitee同步账号json文件
@app.route('/api/upload_json_file22', methods=['POST'])
def upload_json_file22():
    return upload_json(request, REDIS_KEY_GITHUB, f"{secret_path}tmp_data22.json")


# 上传webdav同步账号json文件
@app.route('/api/upload_json_file23', methods=['POST'])
def upload_json_file23():
    return upload_json(request, REDIS_KEY_WEBDAV, f"{secret_path}tmp_data23.json")


# 上传youtube直播源json文件
@app.route('/api/upload_json_file24', methods=['POST'])
def upload_json_file24():
    return upload_json(request, REDIS_KEY_YOUTUBE, f"{secret_path}tmp_data24.json")


# 上传bilibili直播源json文件
@app.route('/api/upload_json_file25', methods=['POST'])
def upload_json_file25():
    return upload_json(request, REDIS_KEY_BILIBILI, f"{secret_path}tmp_data25.json")


# 上传douyu直播源json文件
@app.route('/api/upload_json_file29', methods=['POST'])
def upload_json_file29():
    return upload_json(request, REDIS_KEY_DOUYU, f"{secret_path}tmp_data30.json")


# 上传alist直播源json文件
@app.route('/api/upload_json_file30', methods=['POST'])
def upload_json_file30():
    return upload_json(request, REDIS_KEY_ALIST, f"{secret_path}tmp_data31.json")


# 上传huya直播源json文件
@app.route('/api/upload_json_file26', methods=['POST'])
def upload_json_file26():
    return upload_json(request, REDIS_KEY_HUYA, f"{secret_path}tmp_data26.json")


# 上传YY直播源json文件
@app.route('/api/upload_json_file27', methods=['POST'])
def upload_json_file27():
    return upload_json(request, REDIS_KEY_YY, f"{secret_path}tmp_data27.json")


# 上传webdav直播源账号密码json文件
@app.route('/api/upload_json_file28', methods=['POST'])
def upload_json_file28():
    return upload_json(request, REDIS_KEY_WEBDAV_M3U, f"{secret_path}tmp_data28.json")


# 上传webdav直播源子目录json文件
@app.route('/api/upload_json_file282', methods=['POST'])
def upload_json_file282():
    return upload_json(request, REDIS_KEY_WEBDAV_PATH_LIST, f"{secret_path}tmp_data29.json")


# 上传节点后端服务器json文件
@app.route('/api/upload_json_file10', methods=['POST'])
def upload_json_file10():
    return upload_json(request, REDIS_KEY_PROXIES_SERVER, f"{secret_path}tmp_data10.json")


# 上传节点远程配置json文件
@app.route('/api/upload_json_file9', methods=['POST'])
def upload_json_file9():
    return upload_json(request, REDIS_KEY_PROXIES_MODEL, f"{secret_path}tmp_data9.json")


# 上传节点配置json文件
@app.route('/api/upload_json_file8', methods=['POST'])
def upload_json_file8():
    return upload_json(request, REDIS_KEY_PROXIES_LINK, f"{secret_path}tmp_data8.json")


# 一键上传全部配置集合文件
@app.route('/api/upload_json_file7', methods=['POST'])
def upload_json_file7():
    return upload_oneKey_json(request)


# 赞助-比特币
@app.route('/api/get_image')
def get_image():
    filename = '/app/img/bitcoin.png'
    return send_file(filename, mimetype='image/png')


# 查询功能开启状态
@app.route("/api/getSwitchstate", methods=['POST'])
def getSwitchstate():
    id = request.json['id']
    global function_dict
    status = function_dict[id]
    return jsonify({"checkresult": status})


# 需要额外操作的
clockArr = ['switch25', 'switch26', 'switch27', 'switch28', 'switch29', 'switch13', 'switch25', 'switch33', 'switch34',
            'switch35']


# 切换功能开关
@app.route('/api/switchstate', methods=['POST'])
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
        switchSingleFunction('switch29', '1')
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
        switchSingleFunction('switch29', '1')
        switchSingleFunction('switch30', '0')
        switchSingleFunction('switch31', '0')
        switchSingleFunction('switch32', '0')
        switchSingleFunction('switch33', '0')
        switchSingleFunction('switch34', '0')
        switchSingleFunction('switch35', '0')
    return 'success'


# 修改DNS并发查询数量
@app.route('/api/savetimeout', methods=['POST'])
def savetimeout():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_DNS_TIMEOUT, int(data))
    dnstimeout[REDIS_KEY_DNS_TIMEOUT] = int(data)
    return "数据已经保存"


# DNS并发查询数
@app.route('/api/gettimeout', methods=['GET'])
def gettimeout():
    num = init_dns_timeout()
    return jsonify({'button': num})


# 修改DNS并发查询数量
@app.route('/api/savequeryThreadNum', methods=['POST'])
def savequeryThreadNum():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_DNS_QUERY_NUM, int(data))
    dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = int(data)
    return "数据已经保存"


# 获取DNS并发查询数量
@app.route('/api/getQueryThreadNum', methods=['GET'])
def getQueryThreadNum():
    num = init_dns_query_num()
    return jsonify({'button': num})


# 导出简易DNS黑名单配置
@app.route('/api/download_json_file13', methods=['GET'])
def download_json_file13():
    return download_json_file_base(REDIS_KEY_DNS_SIMPLE_BLACKLIST, f"{secret_path}temp_dnssimpleblacklist.json")


# 删除DNS简易黑名单
@app.route('/api/deletewm3u13', methods=['POST'])
def deletewm3u13():
    redis_add(REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG, 1)
    return dellist(request, REDIS_KEY_DNS_SIMPLE_BLACKLIST)


# 删除youtube直播源
@app.route('/api/deletewm3u24', methods=['POST'])
def deletewm3u24():
    deleteurl = request.json.get('deleteurl')
    del redisKeyYoutube[deleteurl]
    return dellist(request, REDIS_KEY_YOUTUBE)


# 删除bilibili直播源
@app.route('/api/deletewm3u25', methods=['POST'])
def deletewm3u25():
    deleteurl = request.json.get('deleteurl')
    del redisKeyBilili[deleteurl]
    return dellist(request, REDIS_KEY_BILIBILI)


# 删除douyu直播源
@app.route('/api/deletewm3u29', methods=['POST'])
def deletewm3u29():
    deleteurl = request.json.get('deleteurl')
    del redisKeyDouyu[deleteurl]
    return dellist(request, REDIS_KEY_DOUYU)


# 删除alist直播源
@app.route('/api/deletewm3u30', methods=['POST'])
def deletewm3u30():
    deleteurl = request.json.get('deleteurl')
    del redisKeyAlist[deleteurl]
    return dellist(request, REDIS_KEY_ALIST)


# 删除huya直播源
@app.route('/api/deletewm3u26', methods=['POST'])
def deletewm3u26():
    deleteurl = request.json.get('deleteurl')
    del redisKeyHuya[deleteurl]
    return dellist(request, REDIS_KEY_HUYA)


# 删除YY直播源
@app.route('/api/deletewm3u27', methods=['POST'])
def deletewm3u27():
    deleteurl = request.json.get('deleteurl')
    del redisKeyYY[deleteurl]
    return dellist(request, REDIS_KEY_YY)


# 删除webdav直播源路径
@app.route('/api/deletewm3u28', methods=['POST'])
def deletewm3u28():
    deleteurl = request.json.get('deleteurl')
    del redisKeyWebDavPathList[deleteurl]
    return dellist(request, REDIS_KEY_WEBDAV_PATH_LIST)


# 添加DNS简易黑名单
@app.route('/api/addnewm3u13', methods=['POST'])
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
def getall13():
    return jsonify(redis_get_map(REDIS_KEY_DNS_SIMPLE_BLACKLIST))


# 拉取全部youtube
@app.route('/api/getall24', methods=['GET'])
def getall24():
    global redisKeyYoutube
    return returnDictCache(REDIS_KEY_YOUTUBE, redisKeyYoutube)


# 拉取全部bilibili
@app.route('/api/getall25', methods=['GET'])
def getall25():
    global redisKeyBilili
    return returnDictCache(REDIS_KEY_BILIBILI, redisKeyBilili)


# 拉取全部douyu
@app.route('/api/getall29', methods=['GET'])
def getall29():
    global redisKeyDouyu
    return returnDictCache(REDIS_KEY_DOUYU, redisKeyDouyu)


# 拉取全部alist
@app.route('/api/getall30', methods=['GET'])
def getall30():
    global redisKeyAlist
    return returnDictCache(REDIS_KEY_ALIST, redisKeyAlist)


# 拉取全部huya
@app.route('/api/getall26', methods=['GET'])
def getall26():
    global redisKeyHuya
    return returnDictCache(REDIS_KEY_HUYA, redisKeyHuya)


# 拉取全部YY
@app.route('/api/getall27', methods=['GET'])
def getall27():
    global redisKeyYY
    return returnDictCache(REDIS_KEY_YY, redisKeyYY)


# 拉取全部webdav直播源全部子路径
@app.route('/api/getall28', methods=['GET'])
def getall28():
    global redisKeyWebDavPathList
    return returnDictCache(REDIS_KEY_WEBDAV_PATH_LIST, redisKeyWebDavPathList)


def returnDictCache(redisKey, cacheDict):
    if len(cacheDict.keys()) > 0:
        return jsonify(cacheDict)
    dict = redis_get_map(redisKey)
    if dict:
        cacheDict.update(dict)
    return jsonify(cacheDict)


# 导出简易DNS白名单配置
@app.route('/api/download_json_file12', methods=['GET'])
def download_json_file12():
    return download_json_file_base(REDIS_KEY_DNS_SIMPLE_WHITELIST, f"{secret_path}temp_dnssimplewhitelist.json")


# 删除DNS简易白名单
@app.route('/api/deletewm3u12', methods=['POST'])
def deletewm3u12():
    redis_add(REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG, 1)
    return dellist(request, REDIS_KEY_DNS_SIMPLE_WHITELIST)


# 添加DNS简易白名单
@app.route('/api/addnewm3u12', methods=['POST'])
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
def getall12():
    return jsonify(redis_get_map(REDIS_KEY_DNS_SIMPLE_WHITELIST))


# 获取主机IP
@app.route('/api/getIP', methods=['GET'])
def getIP():
    num = init_IP()
    return jsonify({'button': num})


# 修改主机IP
@app.route('/api/changeIP', methods=['POST'])
def changeIP():
    data = request.json['selected_button']
    if data == "":
        data = getMasterIp()
    redis_add(REDIS_KEY_IP, data)
    ip[REDIS_KEY_IP] = data
    update_webdav_fake_url()
    return "数据已经保存"


# 导出m3u白名单配置
@app.route('/api/download_json_file11', methods=['GET'])
def download_json_file11():
    return download_json_file_base(REDIS_KEY_M3U_WHITELIST, f"{secret_path}temp_m3uwhitelist.json")


# 导出m3u白名单分组优先级配置
@app.route('/api/download_json_file16', methods=['GET'])
def download_json_file16():
    return download_json_file_base(REDIS_KEY_M3U_WHITELIST_RANK, f"{secret_path}temp_m3uwhiteranklist.json")


# 导出下载加密上传配置
@app.route('/api/download_json_file17', methods=['GET'])
def download_json_file17():
    return download_json_file_base(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME,
                                   f"{secret_path}temp_downloadAndSecretUpload.json")


# 导出下载解密配置
@app.route('/api/download_json_file18', methods=['GET'])
def download_json_file18():
    return download_json_file_base(REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME,
                                   f"{secret_path}temp_downloadAndDeSecret.json")


# 导出订阅重命名配置
@app.route('/api/download_json_file19', methods=['GET'])
def download_json_file19():
    return download_json_file_base(REDIS_KEY_FILE_NAME,
                                   f"{secret_path}temp_subscribeName.json")


# 导出订阅密码锁配置
@app.route('/api/download_json_file20', methods=['GET'])
def download_json_file20():
    return download_json_file_base(REDIS_KEY_SECRET_PASS_NOW,
                                   f"{secret_path}temp_subscribePass.json")


# 导出gitee账号配置
@app.route('/api/download_json_file21', methods=['GET'])
def download_json_file21():
    return download_json_file_base(REDIS_KEY_GITEE,
                                   f"{secret_path}temp_outputGitee.json")


# 导出github账号配置
@app.route('/api/download_json_file22', methods=['GET'])
def download_json_file22():
    return download_json_file_base(REDIS_KEY_GITHUB,
                                   f"{secret_path}temp_outputGithub.json")


# 导出webdav账号配置
@app.route('/api/download_json_file23', methods=['GET'])
def download_json_file23():
    return download_json_file_base(REDIS_KEY_WEBDAV,
                                   f"{secret_path}temp_outputWebdav.json")


# 导出youtube直播源配置
@app.route('/api/download_json_file24', methods=['GET'])
def download_json_file24():
    return download_json_file_base(REDIS_KEY_YOUTUBE,
                                   f"{secret_path}temp_youtube_m3u.json")


# 导出bilibili直播源配置
@app.route('/api/download_json_file25', methods=['GET'])
def download_json_file25():
    return download_json_file_base(REDIS_KEY_BILIBILI,
                                   f"{secret_path}temp_bilibili_m3u.json")


# 导出douyu直播源配置
@app.route('/api/download_json_file29', methods=['GET'])
def download_json_file29():
    return download_json_file_base(REDIS_KEY_DOUYU,
                                   f"{secret_path}temp_douyu_m3u.json")


# 导出alist直播源配置
@app.route('/api/download_json_file30', methods=['GET'])
def download_json_file30():
    return download_json_file_base(REDIS_KEY_ALIST,
                                   f"{secret_path}temp_alist_m3u.json")


# 导出huya直播源配置
@app.route('/api/download_json_file26', methods=['GET'])
def download_json_file26():
    return download_json_file_base(REDIS_KEY_HUYA,
                                   f"{secret_path}temp_huya_m3u.json")


# 导出YY直播源配置
@app.route('/api/download_json_file27', methods=['GET'])
def download_json_file27():
    return download_json_file_base(REDIS_KEY_YY,
                                   f"{secret_path}temp_YY_m3u.json")


# 导出WEBDAV直播源账号密码配置
@app.route('/api/download_json_file28', methods=['GET'])
def download_json_file28():
    return download_json_file_base(REDIS_KEY_WEBDAV_M3U,
                                   f"{secret_path}temp_WEBDAV_m3u.json")


# 导出WEBDAV直播源子路径配置
@app.route('/api/download_json_file282', methods=['GET'])
def download_json_file282():
    return download_json_file_base(REDIS_KEY_WEBDAV_PATH_LIST,
                                   f"{secret_path}temp_WEBDAV_m3u_path.json")


# 导出m3u黑名单配置
@app.route('/api/download_json_file15', methods=['GET'])
def download_json_file15():
    return download_json_file_base(REDIS_KEY_M3U_BLACKLIST, f"{secret_path}temp_m3ublacklist.json")


# 删除M3U白名单
@app.route('/api/deletewm3u11', methods=['POST'])
def deletewm3u11():
    deleteurl = request.json.get('deleteurl')
    group = m3u_whitlist.get(deleteurl)
    del m3u_whitlist[deleteurl]
    checkAndRemoveM3uRank(group)
    return dellist(request, REDIS_KEY_M3U_WHITELIST)


# 删除M3U白名单分组优先级
@app.route('/api/deletewm3u16', methods=['POST'])
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
def deletewm3u15():
    deleteurl = request.json.get('deleteurl')
    del m3u_blacklist[deleteurl]
    return dellist(request, REDIS_KEY_M3U_BLACKLIST)


# 删除单个下载加密上传
@app.route('/api/deletewm3u17', methods=['POST'])
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
def addnewm3u24():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    redisKeyYoutube[addurl] = name
    return addlist(request, REDIS_KEY_YOUTUBE)


# 添加bilibili直播源
@app.route('/api/addnewm3u25', methods=['POST'])
def addnewm3u25():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyBilili
    redisKeyBilili[addurl] = name
    return addlist(request, REDIS_KEY_BILIBILI)


# 添加douyu直播源
@app.route('/api/addnewm3u29', methods=['POST'])
def addnewm3u29():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyDouyu
    redisKeyDouyu[addurl] = name
    return addlist(request, REDIS_KEY_DOUYU)


# 添加alist直播源
@app.route('/api/addnewm3u30', methods=['POST'])
def addnewm3u30():
    addurl = request.json.get('addurl')
    if not addurl.startswith('http'):
        addurl = 'https://' + addurl
    if not addurl.endswith('/'):
        addurl = addurl + '/'
    name = request.json.get('name')
    global redisKeyAlist
    redisKeyAlist[addurl] = name

    my_dict = {addurl: name}
    redis_add_map(REDIS_KEY_ALIST, my_dict)
    return jsonify({'addresult': "add success"})


# 添加huya直播源
@app.route('/api/addnewm3u26', methods=['POST'])
def addnewm3u26():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyHuya
    redisKeyHuya[addurl] = name
    return addlist(request, REDIS_KEY_HUYA)


# 添加YY直播源
@app.route('/api/addnewm3u27', methods=['POST'])
def addnewm3u27():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyYY
    redisKeyYY[addurl] = name
    return addlist(request, REDIS_KEY_YY)


# 添加webdav直播源路径
@app.route('/api/addnewm3u28', methods=['POST'])
def addnewm3u28():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    global redisKeyWebDavPathList
    redisKeyWebDavPathList[addurl] = name
    return addlist(request, REDIS_KEY_WEBDAV_PATH_LIST)


# 添加M3U白名单分组优先级
@app.route('/api/addnewm3u16', methods=['POST'])
def addnewm3u16():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    checkAndUpdateM3uRank(addurl, name)
    return jsonify({'addresult': "add success"})


# 添加下载加密上传-特殊字典结构保存到redis
@app.route('/api/addnewm3u17', methods=['POST'])
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
def addnewm3u15():
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    m3u_blacklist[addurl] = name
    return addlist(request, REDIS_KEY_M3U_BLACKLIST)


# 拉取全部m3u白名单配置
@app.route('/api/getall11', methods=['GET'])
def getall11():
    init_m3u_whitelist()
    return jsonify(m3u_whitlist)


# 拉取全部m3u白名单分组优先级配置
@app.route('/api/getall16', methods=['GET'])
def getall16():
    init_m3u_whitelist()
    return jsonify(m3u_whitlist_rank)


# 拉取全部下载加密上传
@app.route('/api/getall17', methods=['GET'])
def getall17():
    return jsonify(downAndSecUploadUrlPassAndName)


# 拉取全部下载解密
@app.route('/api/getall18', methods=['GET'])
def getall18():
    return jsonify(downAndDeSecUrlPassAndName)


# 拉取全部m3u黑名单配置
@app.route('/api/getall15', methods=['GET'])
def getall15():
    init_m3u_blacklist()
    return jsonify(m3u_blacklist)


# 通用获取同步账户数据-cachekey,flag(bbs-gitee,pps-github,lls-webdav)
@app.route('/api/getSyncAccountData', methods=['POST'])
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
    elif type == 'm3u':
        global redisKeyWebDavM3u
        num = init_gitee(cacheKey, REDIS_KEY_WEBDAV_M3U, redisKeyWebDavM3u)
        return jsonify({'password': num})


# 修改同步账户数据    gitee-bbs github-pps webdav-lls
@app.route('/api/changeSyncData', methods=['POST'])
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
    elif type == 'm3u':
        global redisKeyWebDavM3u
        update_gitee(cacheKey, value, REDIS_KEY_WEBDAV_M3U, redisKeyWebDavM3u)
    return "数据已经保存"


# 通用随机订阅密码切换
@app.route("/api/changeSubscribePassword", methods=['POST'])
def changeSubscribePassword():
    cacheKey = request.json['cacheKey']
    num = update_m3u_subscribe_pass(cacheKey)
    return jsonify({"password": num})


# 通用随机订阅密码切换-下载加密上传功能
@app.route("/api/changeSubscribePassword2", methods=['POST'])
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
def getFileName():
    cacheKey = request.json['cacheKey']
    num = getFileNameByTagName(cacheKey)
    return jsonify({"password": num})


# 通用订阅文件名字手动修改
@app.route("/api/changeFileName", methods=['POST'])
def changeFileName():
    cacheKey = request.json['cacheKey']
    newName = request.json['inputvalue']
    num = changeFileName2(cacheKey, newName)
    return jsonify({"password": num})


# 通用订阅密码手动修改
@app.route("/api/changeSubscribePasswordByHand", methods=['POST'])
def changeSubscribePasswordByHand():
    cacheKey = request.json['cacheKey']
    password = request.json['inputvalue']
    num = update_m3u_subscribe_pass_by_hand(cacheKey, password)
    return jsonify({"password": num})


# 获取外国DNS端口
@app.route('/api/getExtraDnsPort', methods=['GET'])
def getExtraDnsPort():
    num = init_extra_dns_port()
    return jsonify({'button': num})


# 修改外国DNS端口
@app.route('/api/saveExtraDnsPort', methods=['POST'])
def saveExtraDnsPort():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_EXTRA_DNS_PORT, int(data))
    extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = int(data)
    redis_add(REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG, 1)
    return "数据已经保存"


# 获取外国DNS服务器
@app.route('/api/getExtraDnsServer', methods=['GET'])
def getExtraDnsServer():
    num = init_extra_dns_server()
    return jsonify({'button': num})


# 修改外国DNS服务器
@app.route('/api/saveExtraDnsServer', methods=['POST'])
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
def getChinaDnsPort():
    num = init_china_dns_port()
    return jsonify({'button': num})


# 修改中国DNS端口
@app.route('/api/savechinaDnsPort', methods=['POST'])
def savechinaDnsPort():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_CHINA_DNS_PORT, int(data))
    chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = int(data)
    redis_add(REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG, 1)
    return "数据已经保存"


# 获取中国DNS服务器
@app.route('/api/getChinaDnsServer', methods=['GET'])
def getChinaDnsServer():
    num = init_china_dns_server()
    return jsonify({'button': num})


# 修改中国DNS服务器
@app.route('/api/savechinaDnsServer', methods=['POST'])
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
def getThreadNum():
    num = init_threads_num()
    return jsonify({'button': num})


# 修改黑白名单并发检测线程数
@app.route('/api/saveThreadS', methods=['POST'])
def saveThreadS():
    data = request.json['selected_button']
    redis_add(REDIS_KEY_THREADS, min(int(data), 1000))
    threadsNum[REDIS_KEY_THREADS] = min(int(data), 1000)
    redis_add(REDIS_KEY_UPDATE_THREAD_NUM_FLAG, 1)
    return "数据已经保存"


# 选择目标转换的远程配置
@app.route('/api/chooseProxyModel', methods=['POST'])
def chooseProxyModel():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_MODEL_CHOSEN] = button
    redis_add_map(REDIS_KEY_PROXIES_MODEL_CHOSEN, dict)
    return "success"


# 选择目标转换的远程服务器
@app.route('/api/chooseProxyServer', methods=['POST'])
def chooseProxyServer():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_SERVER_CHOSEN] = button
    redis_add_map(REDIS_KEY_PROXIES_SERVER_CHOSEN, dict)
    return "success"


# 服务器启动时加载选择的配置
@app.route('/api/getSelectedModel', methods=['GET'])
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
def reloadProxyModels():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_SERVER))


# 导出节点远程订阅配置
@app.route('/api/download_json_file10', methods=['GET'])
def download_json_file10():
    return download_json_file_base(REDIS_KEY_PROXIES_SERVER, f"{secret_path}temp_proxyserverlistlink.json")


# 删除节点远程后端服务器订阅
@app.route('/api/deletewm3u10', methods=['POST'])
def deletewm3u10():
    returnJson = dellist(request, REDIS_KEY_PROXIES_SERVER)
    setRandomValueChosen(REDIS_KEY_PROXIES_SERVER, REDIS_KEY_PROXIES_SERVER_CHOSEN)
    return returnJson


# 添加节点后端订阅
@app.route('/api/addnewm3u10', methods=['POST'])
def addnewm3u10():
    return addlist(request, REDIS_KEY_PROXIES_SERVER)


# 拉取全部后端服务器配置
@app.route('/api/getall10', methods=['GET'])
def getall10():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_SERVER))


# 导出节点远程订阅配置
@app.route('/api/download_json_file9', methods=['GET'])
def download_json_file9():
    return download_json_file_base(REDIS_KEY_PROXIES_MODEL, f"{secret_path}temp_proxyremotemodellistlink.json")


# 删除节点远程配置订阅
@app.route('/api/deletewm3u9', methods=['POST'])
def deletewm3u9():
    returnJson = dellist(request, REDIS_KEY_PROXIES_MODEL)
    setRandomValueChosen(REDIS_KEY_PROXIES_MODEL, REDIS_KEY_PROXIES_MODEL_CHOSEN)
    return returnJson


# 添加节点远程配置订阅
@app.route('/api/addnewm3u9', methods=['POST'])
def addnewm3u9():
    return addlist(request, REDIS_KEY_PROXIES_MODEL)


# 拉取全部节点订阅远程配置
@app.route('/api/getall9', methods=['GET'])
def getall9():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_MODEL))


# 服务器启动时加载选择的节点类型id
@app.route('/api/getSelectedButtonId', methods=['GET'])
def getSelectedButtonId():
    button = getProxyButton()
    return jsonify({'button': button})


# 选择目标转换的节点类型id
@app.route('/api/chooseProxy', methods=['POST'])
def chooseProxy():
    button = request.json.get('selected_button')
    dict = {}
    dict[REDIS_KEY_PROXIES_TYPE] = button
    redis_add_map(REDIS_KEY_PROXIES_TYPE, dict)
    return "success"


# 删除节点订阅
@app.route('/api/deletewm3u8', methods=['POST'])
def deletewm3u8():
    return dellist(request, REDIS_KEY_PROXIES_LINK)


# 添加节点订阅
@app.route('/api/addnewm3u8', methods=['POST'])
def addnewm3u8():
    return addlist(request, REDIS_KEY_PROXIES_LINK)


# 拉取全部节点订阅
@app.route('/api/getall8', methods=['GET'])
def getall8():
    return jsonify(redis_get_map(REDIS_KEY_PROXIES_LINK))


# 导出节点订阅配置
@app.route('/api/download_json_file8', methods=['GET'])
def download_json_file8():
    return download_json_file_base(REDIS_KEY_PROXIES_LINK, f"{secret_path}temp_proxieslistlink.json")


# 全部节点订阅链接超融合
@app.route('/api/chaoronghe6', methods=['GET'])
def chaoronghe6():
    try:
        return chaorongheProxies(f"{secret_path}{getFileNameByTagName('proxyConfig')}.yaml")
    except:
        return "empty"


# 简易DNS黑名单超融合：op黑名单代理域名+代理规则
@app.route('/api/chaoronghe7', methods=['GET'])
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
    left_dict = {k: v for k, v in redisKeyBilili.items() if k not in m3u_dict}
    if len(left_dict) == 0:
        return m3u_dict
    m3u_dict2 = await download_file5_single(left_dict.keys(), mintimeout, maxTimeout)
    if len(m3u_dict2) > 0:
        m3u_dict.update(m3u_dict2)
    return m3u_dict


SIGNAL_FULL_ALIVE = 'allAlive'


async def download_files10_single(ids, mintimeout, maxTimeout):
    m3u_dict = {}
    try:
        sem = asyncio.Semaphore(1000)  # 限制TCP连接的数量为100个
        async with aiohttp.ClientSession() as session:
            tasks = []
            for id in ids:
                task = asyncio.ensure_future(grab10(session, id, m3u_dict, sem, mintimeout, maxTimeout))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"douyu Failed to fetch files. Error: {e}")
    return m3u_dict


async def download_files10():
    global redisKeyDouyu
    ids = redisKeyDouyu.keys()
    mintimeout = int(getFileNameByTagName('minTimeout'))
    maxTimeout = int(getFileNameByTagName('maxTimeout'))
    m3u_dict = await download_files10_single(ids, mintimeout, maxTimeout)
    left_dict = {k: v for k, v in redisKeyDouyu.items() if k not in m3u_dict}
    if len(left_dict) == 0:
        return m3u_dict
    m3u_dict2 = await download_files10_single(left_dict.keys(), mintimeout, maxTimeout)
    if len(m3u_dict2) > 0:
        m3u_dict.update(m3u_dict2)
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
    left_dict = {k: v for k, v in redisKeyHuya.items() if k not in m3u_dict}
    if len(left_dict) == 0:
        return m3u_dict
    m3u_dict2 = await download_files6_single(left_dict.keys(), mintimeout, maxTimeout)
    if len(m3u_dict2) > 0:
        m3u_dict.update(m3u_dict2)
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
    left_dict = {k: v for k, v in redisKeyYY.items() if k not in m3u_dict}
    if len(left_dict) == 0:
        return m3u_dict
    m3u_dict2 = await download_files7_single(left_dict.keys(), mintimeout, maxTimeout)
    if len(m3u_dict2) > 0:
        m3u_dict.update(m3u_dict2)
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


did = '10000000000000000000000000001501'


async def get_pre(rid, session, rate_list, t13, sem, mintimeout, maxTimeout):
    url = 'https://playweb.douyucdn.cn/lapi/live/hlsH5Preview/' + rid
    data = {
        'rid': rid,
        'did': did
    }
    auth = hashlib.md5((rid + t13).encode('utf-8')).hexdigest()
    headers = {
        'rid': rid,
        'time': t13,
        'auth': auth
    }
    try:
        async with sem, session.post(url, headers=headers, data=data, timeout=mintimeout) as response:
            res = await response.json()
    except asyncio.TimeoutError:
        t13 = str(int((time.time() * 1000)))
        headers['time'] = t13
        async with sem, session.post(url, headers=headers, data=data, timeout=maxTimeout) as response:
            res = await response.json()
    error = res['error']
    data = res['data']
    try:
        for i in res['data']['settings']:
            rate_list.append(i)
    except:
        pass
    key = ''
    if data:
        rtmp_live = data['rtmp_live']
        key = re.search(
            r'(\d{1,8}[0-9a-zA-Z]+)_?\d{0,4}(/playlist|.m3u8)', rtmp_live).group(1)
    return error, key


async def get_js(id, res, did, t10, session, rate_list, sem, mintimeout, maxTimeout):
    result = re.search(
        r'(function ub98484234.*)\s(var.*)', res).group()
    func_ub9 = re.sub(r'eval.*;}', 'strc;}', result)
    js = execjs.compile(func_ub9)
    res = js.call('ub98484234')

    v = re.search(r'v=(\d+)', res).group(1)
    rb = hashlib.md5((id + did + t10 + v).encode('utf-8')).hexdigest()

    func_sign = re.sub(r'return rt;}\);?', 'return rt;}', res)
    func_sign = func_sign.replace('(function (', 'function sign(')
    func_sign = func_sign.replace(
        'CryptoJS.MD5(cb).toString()', '"' + rb + '"')

    js = execjs.compile(func_sign)
    params = js.call('sign', id, did, t10)
    params += '&ver=219032101&rid={}&rate=-1'.format(id)

    url = 'https://m.douyu.com/api/room/ratestream'
    try:
        async with sem, session.post(url, params=params, timeout=mintimeout) as response:
            res2 = await response.text()
    except asyncio.TimeoutError:
        t10 = str(int(time.time()))
        rb2 = hashlib.md5((id + did + t10 + v).encode('utf-8')).hexdigest()
        func_sign2 = re.sub(r'return rt;}\);?', 'return rt;}', res)
        func_sign2 = func_sign2.replace('(function (', 'function sign(')
        func_sign2 = func_sign2.replace(
            'CryptoJS.MD5(cb).toString()', '"' + rb2 + '"')
        js2 = execjs.compile(func_sign2)
        params2 = js2.call('sign', id, did, t10)
        params2 += '&ver=219032101&rid={}&rate=-1'.format(id)
        async with sem, session.post(url, params=params2, timeout=maxTimeout) as response:
            res2 = await response.text()
    json_ = json.loads(res2)
    try:
        for i in json_['data']['settings']:
            rate_list.append(i)
    except:
        pass
    key = re.search(
        r'(\d{1,8}[0-9a-zA-Z]+)_?\d{0,4}(.m3u8|/playlist)', res2).group(1)
    return key


async def grab10(session, id, m3u_dict, sem, mintimeout, maxTimeout):
    try:
        arr = []
        rate_list = []
        huya_room_url = 'https://m.douyu.com/{}'.format(id)
        try:
            async with sem, session.get(huya_room_url, timeout=mintimeout) as response:
                res = await response.text()
        except asyncio.TimeoutError:
            async with sem, session.get(huya_room_url, timeout=maxTimeout) as response:
                res = await response.text()
        result = re.search(r'rid":(\d{1,8}),"vipId', res)
        if result:
            try:
                rid = result.group(1)
            except Exception as e:
                return
        else:
            return
        t13 = str(int((time.time() * 1000)))
        try:
            error, key = await get_pre(rid, session, rate_list, t13, sem, mintimeout, maxTimeout)
        except Exception as e:
            return
        if error == 0:
            pass
        elif error == 102:
            return
        elif error == 104:
            return
        else:
            t10 = str(int(time.time()))
            try:
                key = await get_js(rid, res, did, t10, session, rate_list, sem, mintimeout, maxTimeout)
            except Exception as e:
                return
        real_lists = []
        real_dict = {}
        if not rate_list:
            # rate_list = [{'name': '蓝光', 'rate': 0, 'high_bit': 1}, {'name': '超清', 'rate': 3, 'high_bit': 0},
            #              {'name': '高清', 'rate': 2, 'high_bit': 0}]
            rate_list = [{'name': '蓝光', 'rate': 0, 'high_bit': 1}]
        for rate in rate_list:
            flyName = "{}_flv".format(rate['name'])
            m3u8Name = "{}_m3u8".format(rate['name'])
            xp2pName = "{}_x_p2p".format(rate['name'])
            aliyunName = "{}_aliyun".format(rate['name'])
            arr.append(flyName)
            arr.append(m3u8Name)
            arr.append(xp2pName)
            arr.append(aliyunName)
            if rate['rate'] != 0:
                flv = {
                    flyName: "http://hdltctwk.douyucdn2.cn/live/{}_{}.flv?uuid=".format(key,
                                                                                        rate[
                                                                                            'rate'] * 1000)}
                m3u8 = {
                    m3u8Name: "http://hdltctwk.douyucdn2.cn/live/{}_{}.m3u8?uuid=".format(key,
                                                                                          rate[
                                                                                              'rate'] * 1000)}
                x_p2p = {
                    xp2pName: "http://hdltctwk.douyucdn2.cn/live/{}_{}.xs?uuid=".format(key,
                                                                                        rate[
                                                                                            'rate'] * 1000)}
                aliyun = {
                    aliyunName: "http://dyscdnali1.douyucdn.cn/live/{}_{}.flv?uuid=".format(
                        key,
                        rate[
                            'rate'] * 1000)}
                real_lists.append(flv)
                real_lists.append(m3u8)
                real_lists.append(x_p2p)
                real_lists.append(aliyun)
            else:
                flv = {flyName: "http://hdltctwk.douyucdn2.cn/live/{}.flv?uuid=".format(key)}
                m3u8 = {m3u8Name: "http://hdltctwk.douyucdn2.cn/live/{}.m3u8?uuid=".format(key)}
                x_p2p = {xp2pName: "http://hdltctwk.douyucdn2.cn/live/{}.xs?uuid=".format(key)}
                aliyun = {
                    aliyunName: "http://dyscdnali1.douyucdn.cn/live/{}.flv?uuid=".format(key)}
                real_lists.append(flv)
                real_lists.append(m3u8)
                real_lists.append(x_p2p)
                real_lists.append(aliyun)
        if real_lists:
            tasks = []
            for real_ in real_lists:
                for key, value in real_.items():
                    task = asyncio.ensure_future(pingM3u(session, value, real_dict, key, sem, mintimeout, maxTimeout))
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
        print(f"douyu An error occurred while processing {id}. Error: {e}")


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
    left_dict = {k: v for k, v in redisKeyYoutube.items() if k not in m3u_dict}
    if len(left_dict) == 0:
        return m3u_dict
    m3u_dict2 = await download_files4_single(left_dict.keys(), mintimeout, maxTimeout)
    if len(m3u_dict2) > 0:
        m3u_dict.update(m3u_dict2)
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
    for item in playlists:
        resolution = item.stream_info.resolution[1]
        if resolution > highest_resolution:
            highest_resolution = resolution

    return highest_resolution


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
        highest_resolution = 0
        while True:
            if 'https://' in content[end - tuner: end]:
                link = content[end - tuner: end]
                start = link.find('https://')
                end = link.find('.m3u8') + 5

                resolution = await get_resolution(session, link[start: end], sem, mintimeout, maxTimeout)
                if resolution and resolution > highest_resolution:
                    highest_quality_link = link[start: end]
                    highest_resolution = resolution
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
def chaoronghe25():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        m3u_dict = loop.run_until_complete(download_files5())
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        elif length == 1:
            if SIGNAL_FULL_ALIVE in m3u_dict.keys():
                return "result"
        ip = init_IP()
        global redisKeyBililiM3u
        global redisKeyBilili
        redisKeyBililiM3uFake = {}
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
        return "result"
    except Exception as e:
        return "empty"


# 生成全部douyu直播源
@app.route('/api/chaoronghe29', methods=['GET'])
def chaoronghe29():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        m3u_dict = loop.run_until_complete(download_files10())
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        elif length == 1:
            if SIGNAL_FULL_ALIVE in m3u_dict.keys():
                return "result"
        ip = init_IP()
        global redisKeyDouyuM3u
        global redisKeyDouyu
        redisKeyDouyuM3uFake = {}
        # fakeurl = f"http://127.0.0.1:5000/douyu/"
        fakeurl = f"http://{ip}:{port_live}/douyu/"
        for id, url in m3u_dict.items():
            try:
                redisKeyDouyuM3u[id] = url
                name = redisKeyDouyu[id]
                link = f'#EXTINF:-1 group-title="Douyu"  tvg-name="{name}",{name}\n'
                redisKeyDouyuM3uFake[f'{fakeurl}{id}.m3u8'] = link
            except:
                pass
        # 同步方法写出全部配置
        distribute_data(redisKeyDouyuM3uFake, f"{secret_path}douyu.m3u", 10)
        redis_add_map(REDIS_KEY_DOUYU_M3U, redisKeyDouyuM3u)
        return "result"
    except Exception as e:
        return "empty"


# 生成全部alist直播源
@app.route('/api/chaoronghe30', methods=['GET'])
def chaoronghe30():
    try:
        global redisKeyAlist
        if len(redisKeyAlist) == 0:
            return "empty"
        global redisKeyAlistM3u
        redisKeyAlistM3u.clear()
        global redisKeyAlistM3uType
        redisKeyAlistM3uType.clear()
        try:
            redis_del_map(REDIS_KEY_Alist_M3U)
        except:
            pass
        try:
            redis_del_map(REDIS_KEY_Alist_M3U_TYPE)
        except:
            pass
        ip = init_IP()
        # fakeurl = f"http://127.0.0.1:5000/alist/"
        fakeurl = f"http://{ip}:{port_live}/alist/"
        pathxxx = f"{secret_path}alist.m3u"
        thread2 = threading.Thread(target=check_alist_file,
                                   args=(redisKeyAlist, redisKeyAlistM3u, fakeurl, pathxxx, redisKeyAlistM3uType))
        thread2.start()
        return "result"
    except Exception as e:
        return "empty"


# 生成全部huyta直播源
@app.route('/api/chaoronghe26', methods=['GET'])
def chaoronghe26():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # 有效直播源,名字/id
        m3u_dict = loop.run_until_complete(download_files6())
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        elif length == 1:
            if SIGNAL_FULL_ALIVE in m3u_dict.keys():
                return "result"
        ip = init_IP()
        global redisKeyHuyaM3u
        global redisKeyHuya
        redisKeyHuyaM3uFake = {}
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
        return "result"
    except Exception as e:
        return "empty"


# 生成全部YY直播源
@app.route('/api/chaoronghe27', methods=['GET'])
def chaoronghe27():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # 有效直播源,名字/id
        m3u_dict = loop.run_until_complete(download_files7())
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        elif length == 1:
            if SIGNAL_FULL_ALIVE in m3u_dict.keys():
                return "result"
        ip = init_IP()
        global redisKeyYYM3u
        global redisKeyYY
        redisKeyYYM3uFake = {}
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
        return "result"
    except Exception as e:
        return "empty"


def getWebDavFileName(filePath):
    arr = filePath.split('/')
    if len(arr) > 1:
        path = arr[-2]
        name = arr[-1]
        arr = name.split('.')
        namestr = ''
        for i in range(len(arr) - 1):
            namestr += arr[i]
        if namestr.isdigit():
            return path + "_" + name
        return name
    return filePath


async def process_child(url, child_list_chunk, fakeurl,
                        redisKeyWebDavPathList):
    groupName = redisKeyWebDavPathList[url]
    for child in child_list_chunk:
        href = child.find('{DAV:}href').text
        if not href.endswith('/'):  # Process only files (not directories)
            file_pathA = '/'.join(href.split('/')[-2:])  # Get the file path from the href
            # Decode any URL-encoded characters in the file name
            file_path = urllib.parse.unquote(file_pathA)
            if not file_path.lower().endswith((".mp4", ".mkv", ".avi", '.ts', '.mov', '.fly', '.mpg', '.wmv', '.m4v',
                                               '.mpeg', '.3gp', '.rmvb', '.rm')):
                # return None
                continue
            name = getWebDavFileName(file_path)
            link = f'#EXTINF:-1 group-title="{groupName}"  tvg-name="{name}",{name}\n'
            # http://127.0.0.1:5000/videos/video1.mp4.m3u8
            str_id = str(uuid.uuid4())
            fake_m3u8 = f'{fakeurl}{str_id}.m3u8'
            # fake_webdav_m3u_dict[fake_m3u8] = link
            async with aiofiles.open(f"{secret_path}webdav.m3u", 'a', encoding='utf-8') as f:  # 异步的方式写入内容
                await f.write(f'{link}{fake_m3u8}\n')
            finalPath = url
            finalPath = finalPath.split('/dav')[0] + urllib.parse.unquote(href)
            finalTrueUrl = quote(finalPath, safe=':/')
            # url编码，跳过:和/，可以解决大部分转移字符的问题
            # true_webdav_m3u_dict_raw_tmp[str_id] = finalTrueUrl
            true_webdav_m3u_dict_raw[str_id] = finalTrueUrl
            type = file_path.split('.')[-1]
            redisKeyWebdavM3uType[str_id] = type
            redis_add_map(REDIS_KEY_webdav_M3U_TYPE, {str_id: type})
            redis_add_map(REDIS_KEY_WEBDAV_M3U_DICT_RAW, {str_id: finalTrueUrl})


async def deal_mutil_webdav_path_m3u(session, url, fakeurl,
                                     auth_header, redisKeyWebDavPathList):
    try:
        async with session.request('PROPFIND', url, auth=auth_header, timeout=10) as response:
            res = await response.text()
        root = fromstring(res)
        childs = root.findall('{DAV:}response')
        await process_child(url, childs, fakeurl, redisKeyWebDavPathList)
    except Exception as e:
        return


async def download_files28():
    username = redisKeyWebDavM3u['username']
    password = redisKeyWebDavM3u['password']
    auth_header = aiohttp.BasicAuth(login=username, password=password)
    fakeurl = getNowWebDavFakeUrl()
    # fakeurl = default_video_prefix
    # http://127.0.0.1:5000/videos/video1.mp4.m3u8
    global redisKeyWebDavPathList
    urls = redisKeyWebDavPathList.keys()

    try:
        # sem = asyncio.Semaphore(100)  # 限制TCP连接的数量为100个
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in urls:
                task = asyncio.ensure_future(
                    deal_mutil_webdav_path_m3u(session, url, fakeurl, auth_header, redisKeyWebDavPathList))
                tasks.append(task)
            await asyncio.gather(*tasks)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Failed to fetch files. Error: {e}")


# 生成全部webdav直播源
@app.route('/api/chaoronghe28', methods=['GET'])
def chaoronghe28():
    try:
        path = f"{secret_path}webdav.m3u"
        if os.path.exists(path):
            os.remove(path)
        # webdav名字，真实地址
        global true_webdav_m3u_dict_raw
        global redisKeyWebdavM3uType
        true_webdav_m3u_dict_raw.clear()
        redisKeyWebdavM3uType.clear()
        redis_del_map(REDIS_KEY_webdav_M3U_TYPE)
        redis_del_map(REDIS_KEY_WEBDAV_M3U_DICT_RAW)

        # fake_webdav_m3u_dict = {}
        # true_webdav_m3u_dict_raw_tmp = {}

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(download_files28())
        # if len(fake_webdav_m3u_dict) == 0:
        #     return "empty"
        # if len(true_webdav_m3u_dict_raw_tmp.keys()) > 0:
        #     true_webdav_m3u_dict_raw.clear()
        #     true_webdav_m3u_dict_raw.update(true_webdav_m3u_dict_raw_tmp)
        #     redis_del_map(REDIS_KEY_WEBDAV_M3U_DICT_RAW)
        #     redis_add_map(REDIS_KEY_WEBDAV_M3U_DICT_RAW, true_webdav_m3u_dict_raw)
        # 同步方法写出全部配置
        # distribute_data(fake_webdav_m3u_dict, f"{secret_path}webdav.m3u", 10)
        return "result"
    except Exception as e:
        return "empty"


# 生成全部youtube直播源
@app.route('/api/chaoronghe24', methods=['GET'])
def chaoronghe24():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        m3u_dict = loop.run_until_complete(download_files4())
        length = len(m3u_dict)
        if length == 0:
            return "empty"
        elif length == 1:
            if SIGNAL_FULL_ALIVE in m3u_dict.keys():
                return "result"
        ip = init_IP()
        global redisKeyYoutubeM3u
        global redisKeyYoutube
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
        return "result"
    except Exception as e:
        return "empty"


# 一键导出全部配置
def delete_all_items_in_db(file_paths):
    for path in file_paths:
        if os.path.exists(path):
            os.remove(path)


@app.route('/api/download_json_file7', methods=['GET'])
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
def deletewm3u6():
    return dellist(request, REDIS_KEY_PASSWORD_LINK)


# 添加密码
@app.route('/api/addnewm3u6', methods=['POST'])
def addnewm3u6():
    return addlist(request, REDIS_KEY_PASSWORD_LINK)


# 导出密码配置
@app.route('/api/download_json_file6', methods=['GET'])
def download_json_file6():
    return download_json_file_base(REDIS_KEY_PASSWORD_LINK, f"{secret_path}temp_passwordlist.json")


# 拉取全部密码
@app.route('/api/getall6', methods=['GET'])
def getall6():
    return jsonify(redis_get_map(REDIS_KEY_PASSWORD_LINK))


# 全部ipv6订阅链接超融合
@app.route('/api/chaoronghe5', methods=['GET'])
def chaoronghe5():
    try:
        return chaorongheBase(REDIS_KEY_WHITELIST_IPV6_LINK, 'process_data_abstract6',
                              REDIS_KEY_WHITELIST_IPV6_DATA, f"{secret_path}{getFileNameByTagName('ipv6')}.txt")
    except:
        return "empty"


# 导出ipv6订阅配置
@app.route('/api/download_json_file5', methods=['GET'])
def download_json_file5():
    return download_json_file_base(REDIS_KEY_WHITELIST_IPV6_LINK, f"{secret_path}temp_ipv6listlink.json")


# 拉取全部ipv6订阅
@app.route('/api/getall5', methods=['GET'])
def getall5():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_IPV6_LINK))


# 删除ipv6订阅
@app.route('/api/deletewm3u5', methods=['POST'])
def deletewm3u5():
    return dellist(request, REDIS_KEY_WHITELIST_IPV6_LINK)


# 添加ipv6订阅
@app.route('/api/addnewm3u5', methods=['POST'])
def addnewm3u5():
    return addlist(request, REDIS_KEY_WHITELIST_IPV6_LINK)


# 删除ipv4订阅
@app.route('/api/deletewm3u4', methods=['POST'])
def deletewm3u4():
    return dellist(request, REDIS_KEY_WHITELIST_IPV4_LINK)


# 添加ipv4订阅
@app.route('/api/addnewm3u4', methods=['POST'])
def addnewm3u4():
    return addlist(request, REDIS_KEY_WHITELIST_IPV4_LINK)


# 全部ipv4订阅链接超融合
@app.route('/api/chaoronghe4', methods=['GET'])
def chaoronghe4():
    try:
        return chaorongheBase(REDIS_KEY_WHITELIST_IPV4_LINK, 'process_data_abstract5',
                              REDIS_KEY_WHITELIST_IPV4_DATA, f"{secret_path}{getFileNameByTagName('ipv4')}.txt")
    except:
        return "empty"


# 导出ipv4订阅配置
@app.route('/api/download_json_file4', methods=['GET'])
def download_json_file4():
    return download_json_file_base(REDIS_KEY_WHITELIST_IPV4_LINK, f"{secret_path}temp_ipv4listlink.json")


# 拉取全部ipv4订阅
@app.route('/api/getall4', methods=['GET'])
def getall4():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_IPV4_LINK))


# 全部域名黑名单订阅链接超融合
@app.route('/api/chaoronghe3', methods=['GET'])
def chaoronghe3():
    try:
        return chaorongheBase(REDIS_KEY_BLACKLIST_LINK, 'process_data_abstract7',
                              REDIS_KEY_BLACKLIST_OPENCLASH_FALLBACK_FILTER_DOMAIN_DATA,
                              f"{secret_path}{getFileNameByTagName('openclashFallbackFilterDomain')}.conf")
        # return chaorongheBase(REDIS_KEY_BLACKLIST_LINK, 'process_data_abstract2',
        #                       REDIS_KEY_BLACKLIST_DATA, "/C.txt")
    except:
        return "empty"


# 导出域名黑名单订阅配置
@app.route('/api/download_json_file3', methods=['GET'])
def download_json_file3():
    return download_json_file_base(REDIS_KEY_BLACKLIST_LINK, f"{secret_path}temp_blacklistlink.json")


# 删除黑名单订阅
@app.route('/api/deletewm3u3', methods=['POST'])
def deletewm3u3():
    return dellist(request, REDIS_KEY_BLACKLIST_LINK)


# 添加黑名单订阅
@app.route('/api/addnewm3u3', methods=['POST'])
def addnewm3u3():
    return addlist(request, REDIS_KEY_BLACKLIST_LINK)


# 拉取全部黑名单订阅
@app.route('/api/getall3', methods=['GET'])
def getall3():
    return jsonify(redis_get_map(REDIS_KEY_BLACKLIST_LINK))


# 导出域名白名单订阅配置
@app.route('/api/download_json_file2', methods=['GET'])
def download_json_file2():
    return download_json_file_base(REDIS_KEY_WHITELIST_LINK, f"{secret_path}temp_whitelistlink.json")


# 全部域名白名单订阅链接超融合
@app.route('/api/chaoronghe2', methods=['GET'])
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
def getall2():
    return jsonify(redis_get_map(REDIS_KEY_WHITELIST_LINK))


# 添加白名单订阅
@app.route('/api/addnewm3u2', methods=['POST'])
def addnewm3u2():
    return addlist(request, REDIS_KEY_WHITELIST_LINK)


# 删除白名单订阅
@app.route('/api/deletewm3u2', methods=['POST'])
def deletewm3u2():
    return dellist(request, REDIS_KEY_WHITELIST_LINK)


# 删除全部本地直播源
@app.route('/api/removeallm3u', methods=['GET'])
def removeallm3u():
    redis_del_map(REDIS_KEY_M3U_DATA)
    return "success"


# 删除全部加密订阅密码历史记录
@app.route('/api/removem3ulinks14', methods=['GET'])
def removem3ulinks14():
    redis_del_map(REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS)
    return "success"


# 删除全部简易DNS黑名单
@app.route('/api/removem3ulinks13', methods=['GET'])
def removem3ulinks13():
    redis_del_map(REDIS_KEY_DNS_SIMPLE_BLACKLIST)
    redis_add(REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG, 1)
    return "success"


# 删除全部youtube直播源
@app.route('/api/removem3ulinks24', methods=['GET'])
def removem3ulinks24():
    redisKeyYoutube.clear()
    redis_del_map(REDIS_KEY_YOUTUBE)
    redisKeyYoutubeM3u.clear()
    redis_del_map(REDIS_KEY_YOUTUBE_M3U)
    return "success"


# 删除全部bilibili直播源
@app.route('/api/removem3ulinks25', methods=['GET'])
def removem3ulinks25():
    redisKeyBilili.clear()
    redis_del_map(REDIS_KEY_BILIBILI)
    redisKeyBililiM3u.clear()
    redis_del_map(REDIS_KEY_BILIBILI_M3U)
    return "success"


# 删除全部douyu直播源
@app.route('/api/removem3ulinks29', methods=['GET'])
def removem3ulinks29():
    redisKeyDouyu.clear()
    redis_del_map(REDIS_KEY_DOUYU)
    redisKeyDouyuM3u.clear()
    redis_del_map(REDIS_KEY_DOUYU_M3U)
    return "success"


# 删除全部alist直播源
@app.route('/api/removem3ulinks30', methods=['GET'])
def removem3ulinks30():
    redisKeyAlist.clear()
    redis_del_map(REDIS_KEY_ALIST)
    redisKeyAlistM3u.clear()
    redis_del_map(REDIS_KEY_Alist_M3U)
    redisKeyAlistM3uType.clear()
    redis_del_map(REDIS_KEY_Alist_M3U_TYPE)
    return "success"


# 删除全部huya直播源
@app.route('/api/removem3ulinks26', methods=['GET'])
def removem3ulinks26():
    redisKeyHuya.clear()
    redis_del_map(REDIS_KEY_HUYA)
    redisKeyHuyaM3u.clear()
    redis_del_map(REDIS_KEY_HUYA_M3U)
    return "success"


# 删除全部YY直播源
@app.route('/api/removem3ulinks27', methods=['GET'])
def removem3ulinks27():
    redisKeyYY.clear()
    redis_del_map(REDIS_KEY_YY)
    redisKeyYYM3u.clear()
    redis_del_map(REDIS_KEY_YY_M3U)
    return "success"


# 删除全部webdav直播源
@app.route('/api/removem3ulinks28', methods=['GET'])
def removem3ulinks28():
    redisKeyWebDavPathList.clear()
    redis_del_map(REDIS_KEY_WEBDAV_PATH_LIST)
    return "success"


# 删除全部webdav直播源切片
@app.route('/api/removem3ulinks282', methods=['GET'])
def removem3ulinks282():
    try:
        cleanup('nope')
        # 没人看推流了，安全起见，删除全部其他切片
        safe_delete_ts('nope')
    except:
        pass
    return "success"


# 删除全部简易DNS白名单
@app.route('/api/removem3ulinks12', methods=['GET'])
def removem3ulinks12():
    redis_del_map(REDIS_KEY_DNS_SIMPLE_WHITELIST)
    redis_add(REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG, 1)
    return "success"


# 删除全部M3U白名单
@app.route('/api/removem3ulinks11', methods=['GET'])
def removem3ulinks11():
    m3u_whitlist.clear()
    redis_del_map(REDIS_KEY_M3U_WHITELIST)
    return "success"


# 删除全部M3U白名单分组优先级
@app.route('/api/removem3ulinks16', methods=['GET'])
def removem3ulinks16():
    m3u_whitlist_rank.clear()
    ranked_m3u_whitelist_set.clear()
    redis_del_map(REDIS_KEY_M3U_WHITELIST_RANK)
    return "success"


# 删除全部下载加密上传
@app.route('/api/removem3ulinks17', methods=['GET'])
def removem3ulinks17():
    downAndSecUploadUrlPassAndName.clear()
    redis_del(REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME)
    return "success"


# 删除全部下载解密
@app.route('/api/removem3ulinks18', methods=['GET'])
def removem3ulinks18():
    downAndDeSecUrlPassAndName.clear()
    redis_del(REDIS_KEY_DOWNLOAD_AND_DESECRET_URL_PASSWORD_NAME)
    return "success"


# 删除全部M3U黑名单
@app.route('/api/removem3ulinks15', methods=['GET'])
def removem3ulinks15():
    m3u_blacklist.clear()
    redis_del_map(REDIS_KEY_M3U_BLACKLIST)
    return "success"


# 删除全部节点后端服务器配置
@app.route('/api/removem3ulinks10', methods=['GET'])
def removem3ulinks10():
    redis_del_map(REDIS_KEY_PROXIES_SERVER)
    redis_del_map(REDIS_KEY_PROXIES_SERVER_CHOSEN)
    initProxyServer()
    return "success"


# 删除全部节点远程配置订阅
@app.route('/api/removem3ulinks9', methods=['GET'])
def removem3ulinks9():
    redis_del_map(REDIS_KEY_PROXIES_MODEL)
    redis_del_map(REDIS_KEY_PROXIES_MODEL_CHOSEN)
    initProxyModel()
    return "success"


# 删除全部节点订阅
@app.route('/api/removem3ulinks8', methods=['GET'])
def removem3ulinks8():
    redis_del_map(REDIS_KEY_PROXIES_LINK)
    return "success"


# 删除全部密码本
@app.route('/api/removem3ulinks6', methods=['GET'])
def removem3ulinks6():
    redis_del_map(REDIS_KEY_PASSWORD_LINK)
    return "success"


# 删除全部ipv6订阅链接
@app.route('/api/removem3ulinks5', methods=['GET'])
def removem3ulinks5():
    redis_del_map(REDIS_KEY_WHITELIST_IPV6_LINK)
    return "success"


# 删除全部ipv4订阅链接
@app.route('/api/removem3ulinks4', methods=['GET'])
def removem3ulinks4():
    redis_del_map(REDIS_KEY_WHITELIST_IPV4_LINK)
    return "success"


# 删除全部白名单源订阅链接
@app.route('/api/removem3ulinks3', methods=['GET'])
def removem3ulinks3():
    redis_del_map(REDIS_KEY_BLACKLIST_LINK)
    return "success"


# 删除全部白名单源订阅链接
@app.route('/api/removem3ulinks2', methods=['GET'])
def removem3ulinks2():
    redis_del_map(REDIS_KEY_WHITELIST_LINK)
    return "success"


# 删除全部直播源订阅链接
@app.route('/api/removem3ulinks', methods=['GET'])
def removem3ulinks():
    redis_del_map(REDIS_KEY_M3U_LINK)
    return "success"


# 导出本地永久直播源
@app.route('/api/download_m3u_file', methods=['GET'])
def download_m3u_file():
    my_dict = redis_get_map(REDIS_KEY_M3U_DATA)
    distribute_data(my_dict, f"{secret_path}temp_m3u.m3u", 10)
    # 发送JSON文件到前端
    return send_file(f"{secret_path}temp_m3u.m3u", as_attachment=True)


# 手动上传m3u文件把直播源保存到数据库
@app.route('/api/upload_m3u_file', methods=['POST'])
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
def deletem3udata():
    # 获取 HTML 页面发送的 POST 请求参数
    deleteurl = request.json.get('deleteurl')
    r.hdel('localm3u', deleteurl)
    return jsonify({'deletem3udata': "delete success"})


# 添加直播源
@app.route('/api/addm3udata', methods=['POST'])
def addm3udata():
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    my_dict = {addurl: name}
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    return jsonify({'addresult': "add success"})


# 拉取全部本地直播源
@app.route('/api/getm3udata', methods=['GET'])
def getm3udata():
    return jsonify(redis_get_map(REDIS_KEY_M3U_DATA))


# 添加直播源到本地
@app.route('/api/savem3uarea', methods=['POST'])
def savem3uarea():
    # 获取 HTML 页面发送的 POST 请求参数
    m3utext = request.json.get('m3utext')
    # 格式优化
    my_dict = formattxt_multithread(m3utext.split("\n"), 'process_data_abstract')
    redis_add_map(REDIS_KEY_M3U_DATA, my_dict)
    return jsonify({'addresult': "add success"})


# 添加直播源订阅
@app.route('/api/addnewm3u', methods=['POST'])
def addnewm3u():
    return addlist(request, REDIS_KEY_M3U_LINK)


# 删除直播源订阅
@app.route('/api/deletewm3u', methods=['POST'])
def deletewm3u():
    return dellist(request, REDIS_KEY_M3U_LINK)


# 拉取全部直播源订阅
@app.route('/api/getall', methods=['GET'])
def getall():
    return jsonify(redis_get_map(REDIS_KEY_M3U_LINK))


# 全部m3u订阅链接超融合
@app.route('/api/chaoronghe', methods=['GET'])
def chaoronghe():
    try:
        return chaorongheBase(REDIS_KEY_M3U_LINK, 'process_data_abstract', REDIS_KEY_M3U_DATA,
                              f"{secret_path}{getFileNameByTagName('allM3u')}.m3u")
    except:
        return "empty"


# 导出直播源订阅配置
@app.route('/api/download_json_file', methods=['GET'])
def download_json_file():
    return download_json_file_base(REDIS_KEY_M3U_LINK, f"{secret_path}temp_m3ulink.json")


# 手动上传m3u文件格式化统一转换
@app.route('/api/process-file', methods=['POST'])
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


def thread_recall_chaoronghe7(second):
    while True:
        chaoronghe7()
        time.sleep(second)


def thread_recall_chaoronghe8(second):
    while True:
        chaoronghe8()
        time.sleep(second)


# ts文件有效时间长度
TS_ALIVE_TIME = 20


def thread_webdav_m3u_killer(second):
    while True:
        now = time.time()
        # 最近一次ts时间
        lastTsTime = ts_dict[mark]
        # 最近一次uuid
        uuid = recordPath['past']
        maxTimeoutIgnoreLastUUID = int(getFileNameByTagName('maxTimeoutIgnoreLastUUID'))
        maxTimeoutIgnoreAllUUID = int(getFileNameByTagName('maxTimeoutIgnoreAllUUID'))
        maxTimeoutTsSeen = int(getFileNameByTagName('maxTimeoutTsSeen'))
        # 超过1分钟没有人访问切片，干掉最近访问uuid之外所有切片数据
        if (now - lastTsTime) > maxTimeoutIgnoreLastUUID and uuid != 'nope':
            cleanup(uuid)
            safe_delete_ts(uuid)
        # 超过1小时没有人访问切片，干掉全部切片数据
        if (now - lastTsTime) > maxTimeoutIgnoreAllUUID and uuid != 'nope':
            cleanup('nope')
            # 没人看推流了，安全起见，删除全部其他切片
            safe_delete_ts('nope')
        # 干掉当前正在观看的视频里已经访问过的ts文件，特征是超过2分钟
        removeList = []
        for tsfile, timesec in ts_dict.items():
            if tsfile == mark:
                continue
            # 已经看过的ts文件保留5分钟
            if (now - timesec) > maxTimeoutTsSeen:
                removeList.append(tsfile)
        safe_delete_single_ts(removeList)
        # 已经过期的ts文件，真正被删除掉的
        if len(removeList) > 0:
            # 真正被删除掉的ts文件，从字典里删除
            for key in removeList:
                try:
                    del ts_dict[key]
                except Exception as e:
                    pass
        time.sleep(second)


def main():
    init_db()
    timer_thread1 = threading.Thread(target=executeM3u, args=(7200,), daemon=True)
    timer_thread1.start()
    timer_thread2 = threading.Thread(target=executeWhitelist, args=(86400,), daemon=True)
    timer_thread2.start()
    timer_thread3 = threading.Thread(target=executeBlacklist, args=(86400,), daemon=True)
    timer_thread3.start()
    timer_thread4 = threading.Thread(target=executeIPV4list, args=(86400,), daemon=True)
    timer_thread4.start()
    timer_thread5 = threading.Thread(target=executeIPV6list, args=(86400,), daemon=True)
    timer_thread5.start()
    timer_thread6 = threading.Thread(target=executeProxylist, args=(10800,), daemon=True)
    timer_thread6.start()
    timer_thread7 = threading.Thread(target=thread_recall_chaoronghe7, args=(600,), daemon=True)
    timer_thread7.start()
    timer_thread8 = threading.Thread(target=thread_recall_chaoronghe8, args=(600,), daemon=True)
    timer_thread8.start()
    timer_thread9 = threading.Thread(target=executeDownUpload, args=(86400,), daemon=True)
    timer_thread9.start()
    timer_thread10 = threading.Thread(target=executeDown, args=(86400,), daemon=True)
    timer_thread10.start()
    timer_thread11 = threading.Thread(target=executeYoutube, args=(3600,), daemon=True)
    timer_thread11.start()
    timer_thread12 = threading.Thread(target=thread_webdav_m3u_killer, args=(10,), daemon=True)
    timer_thread12.start()
    # 启动工作线程消费上传数据至gitee
    t = threading.Thread(target=worker_gitee, daemon=True)
    t.start()
    # 启动工作线程消费上传数据至github
    t2 = threading.Thread(target=worker_github, daemon=True)
    t2.start()
    # 启动工作线程消费上传数据至webdav
    t3 = threading.Thread(target=worker_webdav, daemon=True)
    t3.start()
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

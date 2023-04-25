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
# import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import aiofiles
import redis
import requests
import time
from urllib.parse import urlparse, unquote
# import yaml
from flask import Flask, jsonify, request, send_file, render_template, send_from_directory

import chardet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
                  'simplewhitelistProxyRule': 'simplewhitelistProxyRule'}

# 单独导入导出使用一个配置,需特殊处理:{{url:{pass,name}}}
# 下载网络配置并且加密后上传:url+加密密钥+加密文件名字
REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME = 'downloadAndSecretUploadUrlPasswordAndName'
downAndSecUploadUrlPassAndName = {}

NORMAL_REDIS_KEY = 'normalRedisKey'
# 全部有redis备份字典key-普通redis结构
allListArr = [REDIS_KEY_M3U_LINK, REDIS_KEY_WHITELIST_LINK, REDIS_KEY_BLACKLIST_LINK, REDIS_KEY_WHITELIST_IPV4_LINK,
              REDIS_KEY_WHITELIST_IPV6_LINK, REDIS_KEY_PASSWORD_LINK, REDIS_KEY_PROXIES_LINK, REDIS_KEY_PROXIES_TYPE,
              REDIS_KEY_PROXIES_MODEL, REDIS_KEY_PROXIES_MODEL_CHOSEN, REDIS_KEY_PROXIES_SERVER,
              REDIS_KEY_PROXIES_SERVER_CHOSEN, REDIS_KEY_GITEE, REDIS_KEY_GITHUB,
              REDIS_KEY_M3U_WHITELIST, REDIS_KEY_SECRET_PASS_NOW, REDIS_KEY_WEBDAV, REDIS_KEY_FILE_NAME,
              REDIS_KEY_M3U_BLACKLIST,
              REDIS_KEY_FUNCTION_DICT, REDIS_KEY_SECRET_SUBSCRIBE_HISTORY_PASS]

SPECIAL_REDIS_KEY = 'specialRedisKey'
specialRedisKey = [REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME]


# redis取出map字典
def redis_get_map(key):
    redis_dict = r.hgetall(key)
    python_dict = {key.decode('utf-8'): value.decode('utf-8') for key, value in redis_dict.items()}
    return python_dict


def importToReloadCache(cachekey, dict):
    if cachekey == REDIS_KEY_GITEE:
        global redisKeyGitee
        redisKeyGitee.clear()
        redisKeyGitee = dict.copy()
    elif cachekey == REDIS_KEY_FILE_NAME:
        global file_name_dict
        file_name_dict.clear()
        file_name_dict = dict.copy()
    elif cachekey == REDIS_KEY_GITHUB:
        global redisKeyGithub
        redisKeyGithub.clear()
        redisKeyGithub = dict.copy()
    elif cachekey == REDIS_KEY_WEBDAV:
        global redisKeyWebDav
        redisKeyWebDav.clear()
        redisKeyWebDav = dict.copy()
    elif cachekey == REDIS_KEY_SECRET_PASS_NOW:
        global redisKeySecretPassNow
        redisKeySecretPassNow.clear()
        redisKeySecretPassNow = dict.copy()
    elif cachekey == REDIS_KEY_FUNCTION_DICT:
        global function_dict
        function_dict.clear()
        function_dict = dict.copy()


# 一键导出全部json配置
def importToReloadCacheForSpecial(finalKey22, finalDict22):
    if finalKey22 == REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME:
        global downAndSecUploadUrlPassAndName
        downAndSecUploadUrlPassAndName.clear()
        downAndSecUploadUrlPassAndName = finalDict22.copy()
        # 序列化成JSON字符串
        json_string = json.dumps(downAndSecUploadUrlPassAndName)
        # 将JSON字符串存储到Redis中
        r.set(finalKey22, json_string)
    pass


def generate_multi_json_string():
    finalDict = {}
    for name in allListArr:
        m3ulink = redis_get_map(name)
        if len(m3ulink) > 0:
            finalDict[name] = m3ulink
    outDict1 = {}
    outDict1[NORMAL_REDIS_KEY] = finalDict
    # my_dict = {"name": "John", "age": 30, "city": "New York"}
    # outDict = {'urlKey': my_dict}  # 改为使用冒号分隔键和值
    finalDict2 = {}
    for name in specialRedisKey:
        # 从Redis中读取JSON字符串
        json_string_redis = r.get(name)
        # 反序列化成Python对象
        my_dict_redis = json.loads(json_string_redis)
        if len(my_dict_redis)>0:
            finalDict2[name] = my_dict_redis
    #finalDict2[REDIS_KEY_DOWNLOAD_AND_SECRET_UPLOAD_URL_PASSWORD_NAME] = outDict
    outDict2 = {}
    outDict2[SPECIAL_REDIS_KEY] = finalDict2
    # 合并字典
    merged_dict = {**outDict1, **outDict2}
    # 将合并后的字典导出成json字符串
    json_string = json.dumps(merged_dict)

    for key, value in json.loads(json_string).items():
        if key in NORMAL_REDIS_KEY:
            for finalKey11, finalDict11 in value.items():
                if len(finalDict11) > 0:
                    importToReloadCache(finalKey11, finalDict11)
        elif key in SPECIAL_REDIS_KEY:
            for finalKey22, finalDict22 in value.items():
                if len(finalDict22) > 0:
                    print(finalDict22)
                    importToReloadCacheForSpecial(finalKey22, finalDict22)
    # print(json_string)


if __name__ == '__main__':
    generate_multi_json_string()

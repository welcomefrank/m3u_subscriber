import concurrent.futures
import queue
import socket
import threading
import time
import dnslib
import redis

r = redis.Redis(host='localhost', port=22772)

# 下载的域名白名单存储到redis服务器里
REDIS_KEY_WHITE_DOMAINS = "whitedomains"
# 白名单总命中缓存规则，数据中等，是实际命中的规则缓存
white_list_tmp_policy = {}
# 白名单总命中缓存，数据最少，是实际访问的域名缓存
white_list_tmp_cache = {}
# 白名单全部数据库数据
white_list_nameserver_policy = {}

# 白名单中国大陆IPV4下载数据
REDIS_KEY_WHITELIST_IPV4_DATA = "whitelistipv4data"
# ipv4总命中缓存网段规则，数据中等，是实际命中的规则缓存
ipv4_list_tmp_policy = {}
# ipv4全部数据库数据
ipv4_list_policy = {}

# ipv4整数数组范围
IPV4_INT_ARR = {}

# 下载的域名黑名单存储到redis服务器里
REDIS_KEY_BLACK_DOMAINS = "blackdomains"
# 黑名单总命中缓存规则，数据中等，是实际命中的规则缓存
black_list_tmp_policy = {}
# 黑名单总命中缓存，数据最少，是实际访问的域名缓存
black_list_tmp_cache = {}
# 黑名单全部数据库数据
black_list_policy = {}

# 简易DNS域名白名单
REDIS_KEY_DNS_SIMPLE_WHITELIST = "dnssimplewhitelist"
# 简易白名单总命中缓存规则，数据中等，是实际命中的规则缓存
white_list_simple_tmp_policy = {}
# 简易白名单总命中缓存，数据最少，是实际访问的域名缓存
white_list_simple_tmp_cache = {}
# 简易白名单全部数据库数据
white_list_simple_nameserver_policy = {}

# 简易DNS域名黑名单
REDIS_KEY_DNS_SIMPLE_BLACKLIST = "dnssimpleblacklist"
# 简易黑名单总命中缓存规则，数据中等，是实际命中的规则缓存
black_list_simple_tmp_policy = {}
# 简易黑名单总命中缓存，数据最少，是实际访问的域名缓存
black_list_simple_tmp_cache = {}
# 简易黑名单全部数据库数据
black_list_simple_policy = {}

# china   api.ttt.sh
ipCheckDomian = ["ip.skk.moe", "ip.swcdn.skk.moe", "api.ipify.org",
                 "api-ipv4.ip.sb", "d.skk.moe", "qqwry.api.skk.moe",
                 "ipinfo.io", "cdn.ipinfo.io", "ip.sb", "api.ttt.sh",
                 "ip-api.com", 'ip.chinaz.com', 'ip.tool.chinaz.com']

# 更新队列，避免阻塞
black_list_simple_policy_queue = queue.Queue(maxsize=100)
white_list_simple_nameserver_policy_queue = queue.Queue(maxsize=100)

black_list_simple_tmp_cache_queue = queue.Queue(maxsize=100)
black_list_simple_tmp_policy_queue = queue.Queue(maxsize=100)

white_list_simple_tmp_cache_queue = queue.Queue(maxsize=100)
white_list_simple_tmp_policy_queue = queue.Queue(maxsize=100)

black_list_tmp_cache_queue = queue.Queue(maxsize=100)
black_list_tmp_policy_queue = queue.Queue(maxsize=100)

white_list_tmp_cache_queue = queue.Queue(maxsize=100)
white_list_tmp_policy_queue = queue.Queue(maxsize=100)


# 添加元素到队列中
def put_element(q, element):
    if not q.full():
        q.put(element)
        # print(f"元素 {element} 已经添加到队列中")
    # else:
    #     print("队列已满，不能添加更多元素")


def clearCache(second):
    while True:
        black_list_simple_tmp_cache.clear()
        black_list_simple_tmp_policy.clear()
        white_list_simple_tmp_cache.clear()
        white_list_simple_tmp_policy.clear()
        black_list_tmp_cache.clear()
        black_list_tmp_policy.clear()
        white_list_tmp_cache.clear()
        white_list_tmp_policy.clear()
        global black_list_simple_policy
        clearAndStoreAtLeast50DataInRedis(REDIS_KEY_DNS_SIMPLE_BLACKLIST, black_list_simple_policy)
        global white_list_simple_nameserver_policy
        clearAndStoreAtLeast50DataInRedis(REDIS_KEY_DNS_SIMPLE_WHITELIST, white_list_simple_nameserver_policy)
        time.sleep(second)


def clearCacheFast(second):
    while True:
        black_list_simple_tmp_cache.clear()
        black_list_simple_tmp_policy.clear()
        white_list_simple_tmp_cache.clear()
        white_list_simple_tmp_policy.clear()
        black_list_tmp_cache.clear()
        black_list_tmp_policy.clear()
        white_list_tmp_cache.clear()
        white_list_tmp_policy.clear()
        time.sleep(second)


# redis删除map字典
def redis_del_map(key):
    r.delete(key)


# 简易dns黑白名单保留最低限度的50条数据
def clearAndStoreAtLeast50DataInRedis(redisKey, cacheDict):
    cacheDict.clear()
    tmpDict = redis_get_map(redisKey)
    count = 0
    data = {}
    for key in tmpDict.keys():
        if count > 50:
            break
        updateSpData(key, cacheDict)
        data[key] = ''
        count = count + 1
    try:
        redis_del_map(redisKey)
    except Exception as e:
        pass
    try:
        redis_add_map(redisKey, data)
    except Exception as e:
        pass


def deal_black_list_simple_tmp_cache_queue(second):
    global black_list_simple_tmp_cache_queue
    global black_list_simple_tmp_cache
    while True:
       deal_tmp_cache_policy_queue(black_list_simple_tmp_cache_queue, black_list_simple_tmp_cache)
       time.sleep(second)


def deal_black_list_simple_tmp_policy_queue(second):
    global black_list_simple_tmp_policy_queue
    global black_list_simple_tmp_policy
    while True:
       deal_tmp_cache_policy_queue(black_list_simple_tmp_policy_queue, black_list_simple_tmp_policy)
       time.sleep(second)


def deal_white_list_simple_tmp_cache_queue(second):
    global white_list_simple_tmp_cache_queue
    global white_list_simple_tmp_cache
    while True:
       deal_tmp_cache_policy_queue(white_list_simple_tmp_cache_queue, white_list_simple_tmp_cache)
       time.sleep(second)


def deal_white_list_simple_tmp_policy_queue(second):
    global white_list_simple_tmp_policy_queue
    global white_list_simple_tmp_policy
    while True:
       deal_tmp_cache_policy_queue(white_list_simple_tmp_policy_queue, white_list_simple_tmp_policy)
       time.sleep(second)


def deal_black_list_tmp_cache_queue(second):
    global black_list_tmp_cache_queue
    global black_list_tmp_cache
    while True:
       deal_tmp_cache_policy_queue(black_list_tmp_cache_queue, black_list_tmp_cache)
       time.sleep(second)


def deal_black_list_tmp_policy_queue(second):
    global black_list_tmp_policy_queue
    global black_list_tmp_policy
    while True:
       deal_tmp_cache_policy_queue(black_list_tmp_policy_queue, black_list_tmp_policy)
       time.sleep(second)


def deal_white_list_tmp_cache_queue(second):
    global white_list_tmp_cache_queue
    global white_list_tmp_cache
    while True:
       deal_tmp_cache_policy_queue(white_list_tmp_cache_queue, white_list_tmp_cache)
       time.sleep(second)


def deal_white_list_tmp_policy_queue(second):
    global white_list_tmp_policy_queue
    global white_list_tmp_policy
    while True:
       deal_tmp_cache_policy_queue(white_list_tmp_policy_queue, white_list_tmp_policy)
       time.sleep(second)


def deal_tmp_cache_policy_queue(queue, dict):
    add_dict = {}
    for i in range(10):
        if not queue.empty():
            domain = queue.get()
            add_dict[domain] = ''
    if len(add_dict) > 0:
        dict.update(add_dict)


# 自动更新黑白名单数据至redis,多线程插入会丢失数据，只能把插数据的操作集中到单个线程
def deal_black_list_simple_policy_queue(second):
    global black_list_simple_policy_queue
    global white_list_simple_nameserver_policy_queue
    global white_list_simple_nameserver_policy
    global black_list_simple_policy
    while True:
        add_dict = {}
        add_dict2 = {}
        for i in range(10):
            if not black_list_simple_policy_queue.empty():
                domain = black_list_simple_policy_queue.get()
                domain = stupidThink(domain)
                add_dict[domain] = ''
            if not white_list_simple_nameserver_policy_queue.empty():
                domain2 = white_list_simple_nameserver_policy_queue.get()
                domain2 = stupidThink(domain2)
                add_dict2[domain2] = ''
        if len(add_dict) > 0:
            redis_add_map(REDIS_KEY_DNS_SIMPLE_BLACKLIST, add_dict)
            for key in add_dict.keys():
                updateSpData(key, black_list_simple_policy)
        if len(add_dict2) > 0:
            redis_add_map(REDIS_KEY_DNS_SIMPLE_WHITELIST, add_dict2)
            for key in add_dict2.keys():
                updateSpData(key, white_list_simple_nameserver_policy)
        time.sleep(second)


# 规则：先查unkown_list_tmp_cache，有的话转发5335,
# 没有再查black_list_tmp_cache，有记录直接转发5335,
# 没有再查white_list_tmp_cache,有记录直接转发5336，
# 没有再查black_list_tmp_policy,命中则更新black_list_tmp_cache，转发5335。
# 没有则查white_list_tmp_policy,命中则更新white_list_tmp_cache，转发5336。
# 没有命中则black_list_policy，查到则更新black_list_tmp_policy，blacl_list_tmp_cache，再转发5335
# 没有命中则white_list_nameserver_policy，查到则更新white_list_tmp_policy，white_list_tmp_cache，再转发5336
# 没有命中则更新unkown_list_tmp_cache，转发给127.0.0.1#5335


# 并发检测白名单黑名单线程数主键
REDIS_KEY_THREADS = "threadsnum"
threadsNum = {REDIS_KEY_THREADS: 100}

MAXTHREAD = 100

# 中国DNS服务器主键
REDIS_KEY_CHINA_DNS_SERVER = "chinadnsserver"
chinadnsserver = {REDIS_KEY_CHINA_DNS_SERVER: ""}

# 中国DNS端口主键
REDIS_KEY_CHINA_DNS_PORT = "chinadnsport"
chinadnsport = {REDIS_KEY_CHINA_DNS_PORT: 5336}

# 外国DNS服务器主键
REDIS_KEY_EXTRA_DNS_SERVER = "extradnsserver"
extradnsserver = {REDIS_KEY_EXTRA_DNS_SERVER: ""}

# 外国DNS端口主键
REDIS_KEY_EXTRA_DNS_PORT = "extradnsport"
extradnsport = {REDIS_KEY_EXTRA_DNS_PORT: 7874}

REDIS_KEY_DNS_QUERY_NUM = "dnsquerynum"
dnsquerynum = {REDIS_KEY_DNS_QUERY_NUM: 150}

REDIS_KEY_DNS_TIMEOUT = "dnstimeout"
dnstimeout = {REDIS_KEY_DNS_TIMEOUT: 20}


# 获取软路由主路由ip
# def getMasterIp():
#     # 获取宿主机IP地址
#     host_ip = socket.gethostbyname(socket.gethostname())
#     # client = docker.from_env()
#     # # 设置要创建容器的参数
#     # container_name = 'my_container_name'
#     # image_name = 'my_image_name'
#     # command = 'python /path/to/my_script.py'
#     # volumes = {'/path/on/host': {'bind': '/path/on/container', 'mode': 'rw'}}
#     # ports = {'8080/tcp': ('0.0.0.0', 8080)}
#     #
#     # # 获取宿主机IP地址
#     # host_ip = socket.gethostbyname(socket.gethostname())
#     #
#     # # 设置容器的host_config属性
#     # host_config = client.api.create_host_config(
#     #     network_mode='host',  # 使用宿主机的网络模式
#     #     extra_hosts={'host.docker.internal': host_ip}  # 添加一个docker内部host和宿主机IP的映射
#     # )
#     #
#     # # 创建容器
#     # container = client.containers.create(
#     #     name=container_name,
#     #     image=image_name,
#     #     command=command,
#     #     volumes=volumes,
#     #     ports=ports,
#     #     host_config=host_config
#     # )
#     #
#     # # 启动容器
#     # container.start()
#     return host_ip

#####################################################ip判断####################################################


# port = 80


# def getHostByName(hostname):
#     #socket.gethostbyname
#     # getaddrinfo() 函数将返回一个包含 (family, type, proto, canonname, sockaddr) 元组的列表
#     addresses = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
#     # 选择列表中的第一个元组，并从中提取 IP 地址
#     ip_address = addresses[0][4][0]
#     return ip_address


# 检测域名是否属于IP网段数组范围
# def check_domain_in_ip_range(ip_ranges, domain):
#     ip = ip_to_int(getHostByName(domain))
#     # 从命中的ip段先查一下
#     ip_range = find_ip_range_cache(ip)
#     # 查不到
#     if ip_range is None:
#         # 去全部ip段查
#         ip_range = find_ip_range(ip_ranges.keys(), ip)
#         return ip_range is not None
#     else:
#         # 命中的ip段查到了返回数据
#         return ip_range


# 检测域名
# def isChinaIPV4(domain):
#     if check_domain_in_ip_range(IPV4_INT_ARR, domain):
#         white_list_tmp_cache[domain] = ""
#         # print("{0} belongs to IP range".format(domain))
#         return True
#     else:
#         # print("{0} does not belong to IP range".format(domain))
#         return False


######################################################ip判断###################################################

# 检测域名是否在记录的简易黑名单域名策略缓存  是-true  不是-false
def inSimpleBlackListPolicyCache(domain_name_str):
    # 在今日已经命中的规则里查找
    for vistedDomain in black_list_simple_tmp_policy.keys():
        # 缓存域名在新域名里有匹配
        if domain_name_str.endswith(vistedDomain):
            if not black_list_simple_tmp_cache_queue.full():
                black_list_simple_tmp_cache_queue.put(domain_name_str)
            # black_list_simple_tmp_cache[domain_name_str] = ""
            return True
    return False


# 检测域名是否在记录的简易黑名单域名缓存  是-true  不是-false
def inSimpleBlackListCache(domain_name_str):
    for recordThiteDomain in black_list_simple_tmp_cache.keys():
        # # 缓存域名在新域名里有匹配
        if domain_name_str.endswith(recordThiteDomain):
            return True
    return False


def removeRepeatList(item_policy):
    # item_policy_set = set(item_policy.keys())
    # deleteitems_policy_set = set(deleteitems_policy.keys())
    # result = sorted(item_policy_set - deleteitems_policy_set)
    # return item_policy.keys()
    return sorted(item_policy)


def getWeakThread(length):
    return min(length, MAXTHREAD)


# 检测域名是否在全部简易黑名单域名策略  是-true  不是-false
def inSimpleBlackListPolicy(domain_name_str):
    sourceDict = findBottomDict(domain_name_str, black_list_simple_policy)
    if sourceDict:
        if len(sourceDict) == 0:
            return False
        items = removeRepeatList(sourceDict)
        length = len(items)
        trueThreadNum = getWeakThread(length)
        # 计算每个线程处理的数据大小
        chunk_size = length // trueThreadNum
        left = length - chunk_size * trueThreadNum
        finalindex = trueThreadNum - 1
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=trueThreadNum) as executor:
                for i in range(trueThreadNum):
                    start_index = i * chunk_size
                    if i == finalindex:
                        end_index = min(start_index + chunk_size + left, length)
                    else:
                        end_index = min(start_index + chunk_size, length)
                    black_list_chunk = items[start_index:end_index]
                    future = executor.submit(check_domain_inSimpleBlackListPolicy, domain_name_str, black_list_chunk)
                    if future.result():
                        return True
        finally:
            executor.shutdown(wait=False)
        return False
    else:
        return False


def check_domain_inSimpleBlackListPolicy(domain_name_str, black_list_chunk):
    try:
        for key in black_list_chunk:
            # 缓存域名在新域名里有匹配
            if domain_name_str.endswith(key):
                if not black_list_simple_tmp_cache_queue.full():
                    black_list_simple_tmp_cache_queue.put(domain_name_str)
                if not black_list_simple_tmp_policy_queue.full():
                    black_list_simple_tmp_policy_queue.put(key)
                # black_list_simple_tmp_cache[domain_name_str] = ""
                # black_list_simple_tmp_policy[key] = ""
                return True
    except Exception as e:
        pass


# 检测域名是否在记录的黑名单域名策略缓存  是-true  不是-false
def inBlackListPolicyCache(domain_name_str):
    # 在今日已经命中的规则里查找
    for vistedDomain in black_list_tmp_policy.keys():
        # 缓存域名在新域名里有匹配
        if domain_name_str.endswith(vistedDomain):
            if not black_list_tmp_cache_queue.full():
                black_list_tmp_cache_queue.put(domain_name_str)
            # black_list_tmp_cache[domain_name_str] = ""
            return True
    return False


# 检测域名是否在记录的黑名单域名缓存  是-true  不是-false
def inBlackListCache(domain_name_str):
    for recordThiteDomain in black_list_tmp_cache.keys():
        # # 缓存域名在新域名里有匹配
        if domain_name_str.endswith(recordThiteDomain):
            return True
    return False


# 检测域名是否在记录的简易白名单域名缓存  是-true  不是-false
def inSimpleWhiteListCache(domain_name_str):
    for recordThiteDomain in white_list_simple_tmp_cache.keys():
        # # 缓存域名在新域名里有匹配
        if domain_name_str.endswith(recordThiteDomain):
            return True
    return False


# 检测域名是否在记录的简易白名单域名策略缓存  是-true  不是-false
def inSimpleWhiteListPolicyCache(domain_name_str):
    # 在今日已经命中的规则里查找
    for vistedDomain in white_list_simple_tmp_policy.keys():
        # 缓存域名在新域名里有匹配
        if domain_name_str.endswith(vistedDomain):
            if not white_list_simple_tmp_cache_queue.full():
                white_list_simple_tmp_cache_queue.put(domain_name_str)
            # white_list_simple_tmp_cache[domain_name_str] = ""
            return True
    return False


# 检测域名是否在全部简易白名单域名策略  是-true  不是-false
def inSimpleWhiteListPolicy(domain_name_str):
    sourceDict = findBottomDict(domain_name_str, white_list_simple_nameserver_policy)
    if sourceDict:
        if len(sourceDict) == 0:
            return False
        items = removeRepeatList(sourceDict)
        length = len(items)
        trueThreadNum = getWeakThread(length)
        # 计算每个线程处理的数据大小
        chunk_size = length // trueThreadNum
        left = length - chunk_size * trueThreadNum
        finalIndex = trueThreadNum - 1
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=trueThreadNum) as executor:
                for i in range(0, trueThreadNum):
                    start_index = i * chunk_size
                    if i == finalIndex:
                        end_index = min(start_index + chunk_size + left, length)
                    else:
                        end_index = min(start_index + chunk_size, length)
                    white_list_chunk = items[start_index:end_index]
                    future = executor.submit(check_domain_inSimpleWhiteListPolicy, domain_name_str, white_list_chunk)
                    if future.result():
                        return True
        finally:
            executor.shutdown(wait=False)
        return False
    else:
        return False


def check_domain_inSimpleWhiteListPolicy(domain_name_str, white_list_chunk):
    try:
        for key in white_list_chunk:
            # 新域名在全部规则里有类似域名，更新whiteDomainPolicy
            if domain_name_str.endswith(key):
                if not white_list_simple_tmp_cache_queue.full():
                    white_list_simple_tmp_cache_queue.put(domain_name_str)
                # white_list_simple_tmp_cache[domain_name_str] = ""
                if not white_list_simple_tmp_policy_queue.full():
                    white_list_simple_tmp_policy_queue.put(key)
                # white_list_simple_tmp_policy[key] = ""
                return True
    except Exception as e:
        pass


# 检测域名是否在记录的白名单域名缓存  是-true  不是-false
def inWhiteListCache(domain_name_str):
    for recordThiteDomain in white_list_tmp_cache.keys():
        # # 缓存域名在新域名里有匹配
        if domain_name_str.endswith(recordThiteDomain):
            return True
    return False


# 检测域名是否在记录的白名单域名策略缓存  是-true  不是-false
def inWhiteListPolicyCache(domain_name_str):
    # 在今日已经命中的规则里查找
    for vistedDomain in white_list_tmp_policy.keys():
        # 缓存域名在新域名里有匹配
        if domain_name_str.endswith(vistedDomain):
            if not white_list_tmp_cache_queue.full():
                white_list_tmp_cache_queue.put(domain_name_str)
            # white_list_tmp_cache[domain_name_str] = ""
            return True
    return False


# 检测域名是否在全部黑名单域名策略  是-true  不是-false
def inBlackListPolicy(domain_name_str):
    sourceDict = findBottomDict(domain_name_str, blacklistSpData)
    if sourceDict:
        if len(sourceDict) == 0:
            return False
        items = removeRepeatList(sourceDict)
        length = len(items)
        trueThreadNum = getWeakThread(length)
        # 计算每个线程处理的数据大小
        chunk_size = length // trueThreadNum
        left = length - chunk_size * trueThreadNum
        finalindex = trueThreadNum - 1
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=trueThreadNum) as executor:
                for i in range(trueThreadNum):
                    start_index = i * chunk_size
                    if i == finalindex:
                        end_index = min(start_index + chunk_size + left, length)
                    else:
                        end_index = min(start_index + chunk_size, length)
                    black_list_chunk = items[start_index:end_index]
                    future = executor.submit(check_domain_inBlackListPolicy, domain_name_str, black_list_chunk)
                    if future.result():
                        return True
        finally:
            executor.shutdown(wait=False)
        return False

    else:
        return False


def check_domain_inBlackListPolicy(domain_name_str, black_list_chunk):
    try:
        for key in black_list_chunk:
            # 缓存域名在新域名里有匹配
            if domain_name_str.endswith(key):
                if not black_list_tmp_cache_queue.full():
                    black_list_tmp_cache_queue.put(domain_name_str)
                if not black_list_tmp_policy_queue.full():
                    black_list_tmp_policy_queue.put(key)
                # black_list_tmp_cache[domain_name_str] = ""
                # black_list_tmp_policy[key] = ""
                return True
    except Exception as e:
        pass


# 检测域名是否在全部白名单域名策略  是-true  不是-false
def inWhiteListPolicy(domain_name_str):
    sourceDict = findBottomDict(domain_name_str, whitelistSpData)
    if sourceDict:
        if len(sourceDict) == 0:
            return False
        items = removeRepeatList(sourceDict)
        length = len(items)
        trueThreadNum = getWeakThread(length)
        # 计算每个线程处理的数据大小
        chunk_size = length // trueThreadNum
        left = length - chunk_size * trueThreadNum
        finalIndex = trueThreadNum - 1
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=trueThreadNum) as executor:
                for i in range(0, trueThreadNum):
                    start_index = i * chunk_size
                    if i == finalIndex:
                        end_index = min(start_index + chunk_size + left, length)
                    else:
                        end_index = min(start_index + chunk_size, length)
                    white_list_chunk = items[start_index:end_index]
                    future = executor.submit(check_domain_inWhiteListPolicy, domain_name_str, white_list_chunk)
                    if future.result():
                        return True
        finally:
            executor.shutdown(wait=False)
        return False

    else:
        return False


def check_domain_inWhiteListPolicy(domain_name_str, white_list_chunk):
    try:
        for key in white_list_chunk:
            # 新域名在全部规则里有类似域名，更新whiteDomainPolicy
            if domain_name_str.endswith(key):
                if not white_list_tmp_cache_queue.full():
                    white_list_tmp_cache_queue.put(domain_name_str)
                if not white_list_tmp_policy_queue.full():
                    white_list_tmp_policy_queue.put(key)
                # white_list_tmp_cache[domain_name_str] = ""
                # white_list_tmp_policy[key] = ""
                return True
    except Exception as e:
        pass


def stupidThink(domain_name):
    try:
        sub_domains = ['.'.join(domain_name.split('.')[i:]) for i in range(len(domain_name.split('.')) - 1)]
    except Exception as e:
        return ''
    # 一级域名,不是顶级域名那种
    domain = sub_domains[-1]
    try:
        for key in ignore_domain:
            # 一级域名有顶级域名，找二级域名
            if domain.startswith(key):
                try:  # 二级域名仍然可能有顶级域名，但很少
                    return sub_domains[-2]
                except Exception as e:
                    return domain
        return domain
    except Exception as e:
        return domain


# 白名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
REDIS_KEY_WHITELIST_DATA_SP = "whitelistdatasp"
# 白名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
whitelistSpData = {}
# 黑名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
REDIS_KEY_BLACKLIST_DATA_SP = "blacklistdatasp"
# 黑名单三段字典:顶级域名,一级域名长度,一级域名首位,一级域名数据
blacklistSpData = {}


# 顶级域名,一级域名开头字母,一级域名长度,一级域名,二级域名,''
# 根据一级域名获取最小字典数据
def findBottomDict(domain_name_str, whitelistSpData):
    try:
        # 有二级域名
        # 二级域名名字,一级域名,顶级域名名字
        start, middle, end = domain_name_str.split('.')
        # 1级域名字符串数组
        arr2 = [char for char in middle]
        # 1级域名字符串数组长度
        length2 = str(len(arr2))
        # 1级域名数组首位字符串
        startStr2 = arr2[0]
        if end not in whitelistSpData.keys():
            return {}
        # 顶级域名字典
        endDict = whitelistSpData[end]
        if startStr2 not in endDict.keys():
            return {}
        # 一级域名开头字母
        weightDict = endDict[startStr2]
        if length2 not in weightDict.keys():
            return {}
        # 一级域名长度
        length1Dict = weightDict[length2]
        if middle not in length1Dict.keys():
            return {}
        # 一级域名
        startStr1Dict = length1Dict[middle]
        if startStr1Dict:
            return startStr1Dict
        else:
            return {}
    except Exception as e:
        # 只有一级域名
        # print(e)
        try:
            # 一级域名名字，顶级域名名字
            start, end = domain_name_str.split('.')
            # 一级域名字符串数组
            arr = [char for char in start]
            # 一级域名字符串数组长度
            length = str(len(arr))
            # 一级域名数组首位字符串
            startStr = arr[0]
            if end not in whitelistSpData.keys():
                return {}
            endDict = whitelistSpData[end]
            if startStr not in endDict.keys():
                return {}
            weightDict = endDict[startStr]
            if length not in weightDict.keys():
                return {}
            lengthDict = weightDict[length]
            if start not in lengthDict.keys():
                return {}
            startStrDict = lengthDict[start]
            if startStrDict:
                return startStrDict
            else:
                return {}
        except Exception as e:
            # 只有顶级域名
            # print(e)
            pass


# 添加元素到队列中
def put_element(q, element):
    if not q.full():
        q.put(element)
        # print(f"元素 {element} 已经添加到队列中")
    # else:
    #     print("队列已满，不能添加更多元素")


ignore_domain = ['com.', 'cn.', 'org.', 'net.', 'edu.', 'gov.', 'mil.', 'int.', 'biz.', 'info.', 'name.', 'pro.',
                 'asia.', 'us.', 'uk.', 'jp.']


# 外国判断  1  1  1  1   0   1   0    0
# 中国判断  1     0      0       1
# 直接信任黑名单规则
# 直接信任白名单规则
# 是中国域名   是-true  不是-false
def isChinaDomain(data):
    dns_msg = dnslib.DNSRecord.parse(data)
    domain_name = dns_msg.q.qname
    domain_name_str = str(domain_name)
    domain_name_str = domain_name_str[:-1]
    # domain_name_str = stupidThink(domain_name_str)
    ###########################################无脑放行IP检测，排除中国的#######################################
    # if domain_name_str in ipCheckDomian:
    #     return False
    ##########################################中国特色顶级域名，申请必须要经过大陆审批通过，默认全部当成大陆域名#############
    if domain_name_str.endswith(".cn") or domain_name_str.endswith(".中国"):
        return True
    ###########################################个人日常冲浪的域名分流策略，自己维护##############################
    # 在已经命中的简易外国域名查找，直接丢给5335
    if inSimpleBlackListCache(domain_name_str):
        return False
    # 在今日已经命中的简易黑名单规则里查找
    if inSimpleBlackListPolicyCache(domain_name_str):
        return False
    # 简易黑名单规则里查找
    if inSimpleBlackListPolicy(domain_name_str):
        return False
    # 在已经命中的简易中国域名查找，直接丢给5336
    if inSimpleWhiteListCache(domain_name_str):
        return True
    # 在今日已经命中的简易白名单规则里查找
    if inSimpleWhiteListPolicyCache(domain_name_str):
        return True
    # 在全部简易白名单规则里查找
    if inSimpleWhiteListPolicy(domain_name_str):
        return True
    ####################################保底查询策略，基于互联网维护的黑白名单域名爬虫数据################################
    # 在已经命中的外国域名查找，直接丢给5335
    if inBlackListCache(domain_name_str):
        checkAndUpdateSimpleList(True, domain_name_str)
        return False
    # 在今日已经命中的黑名单规则里查找
    if inBlackListPolicyCache(domain_name_str):
        checkAndUpdateSimpleList(True, domain_name_str)
        return False
    # 黑名单规则里查找
    if inBlackListPolicy(domain_name_str):
        checkAndUpdateSimpleList(True, domain_name_str)
        return False
    # 在已经命中的中国域名查找，直接丢给5336
    if inWhiteListCache(domain_name_str):
        checkAndUpdateSimpleList(False, domain_name_str)
        return True
    # 在今日已经命中的白名单规则里查找
    if inWhiteListPolicyCache(domain_name_str):
        checkAndUpdateSimpleList(False, domain_name_str)
        return True
    # 在全部白名单规则里查找
    if inWhiteListPolicy(domain_name_str):
        checkAndUpdateSimpleList(False, domain_name_str)
        return True
    ############################################后背隐藏能源:基于超大量的中国ip去对比查找############################
    # 在ipv4网段规则里查找，有个祖父悖论的问题，根据域名查ip需要联网，妈的
    # if isChinaIPV4(domain_name_str):
    #     checkAndUpdateSimpleList(False, domain_name_str)
    #     return True
    return False


def simpleDomain(domain_name):
    if domain_name.encode().startswith(b"www."):
        simple_domain_name = domain_name.substring(4)
    else:
        simple_domain_name = domain_name
    return simple_domain_name


def redis_get_map(key):
    redis_dict = r.hgetall(key)
    python_dict = {key.decode('utf-8'): value.decode('utf-8') for key, value in redis_dict.items()}
    return python_dict


def initSimpleBlackList():
    global black_list_simple_policy
    simpleblacklist = redis_get_map(REDIS_KEY_DNS_SIMPLE_BLACKLIST)
    if simpleblacklist and len(simpleblacklist) > 0:
        black_list_simple_policy.clear()
        for domain in simpleblacklist:
            updateSpData(domain, black_list_simple_policy)


def initSimpleWhiteList():
    global white_list_simple_nameserver_policy
    simplewhitelist = redis_get_map(REDIS_KEY_DNS_SIMPLE_WHITELIST)
    if simplewhitelist and len(simplewhitelist) > 0:
        white_list_simple_nameserver_policy.clear()
        for domain in simplewhitelist:
            # updateSimpleWhiteListSpData(domain)
            updateSpData(domain, white_list_simple_nameserver_policy)


# 顶级域名,一级域名开头字母,一级域名长度,一级域名,二级域名,''
# 顶级域名,一级域名开头字母,一级域名长度,一级域名,'',''
def updateSpData(domain_name_str, dict):
    try:
        # 二级域名名字,一级域名名字，顶级域名名字
        start, middle, end = domain_name_str.split('.')
        # 一级域名字符串数组
        arr2 = [char for char in middle]
        # 一级域名字符串数组长度
        length2 = str(len(arr2))
        # 一级域名数组首位字符串
        startStr2 = arr2[0]
        # 顶级域名字典
        if end not in dict.keys():
            dict[end] = {}
        # 一级域名开头字母
        endDict1 = dict[end]
        if startStr2 not in endDict1.keys():
            endDict1[startStr2] = {}
        # 一级域名长度
        weightDict = endDict1[startStr2]
        if length2 not in weightDict.keys():
            weightDict[length2] = {}
        # 一级域名
        length1Dict = weightDict[length2]
        if middle not in length1Dict.keys():
            length1Dict[middle] = {}
        # 二级域名字典
        startStr1Dict = length1Dict[middle]
        startStr1Dict[domain_name_str] = ''
    except Exception as e:
        try:
            # 顶级域名,一级域名开头字母,一级域名长度,一级域名,''
            # print(e)
            # 一级域名名字，顶级域名名字
            start, end = domain_name_str.split('.')
            # 一级域名字符串数组
            arr = [char for char in start]
            # 一级域名字符串数组长度
            length = str(len(arr))
            # 一级域名数组首位字符串
            startStr = arr[0]
            # 顶级域名字典集合
            if end not in dict:
                dict[end] = {}
            # 目标顶级域名字典
            endDict = dict[end]
            if startStr not in endDict.keys():
                endDict[startStr] = {}
            # 一级域名开头字母集合
            weightDict = endDict[startStr]
            if length not in weightDict.keys():
                weightDict[length] = {}
            # 一级域名长度集合
            lengthDict = weightDict[length]
            if start not in lengthDict:
                lengthDict[start] = {}
            # 一级域名集合
            startStrDict = lengthDict[start]
            startStrDict[domain_name_str] = ''
        except Exception as e:
            # 只有顶级域名
            # print(e)
            pass


def initWhiteListSP():
    global whitelistSpData
    whitelistSP = redis_get_map(REDIS_KEY_WHITELIST_DATA_SP)
    if whitelistSP and len(whitelistSP) > 0:
        whitelistSpData.clear()
        for domain in whitelistSP:
            updateSpData(domain, whitelistSpData)


def initBlackListSP():
    global blacklistSpData
    blacklistSP = redis_get_map(REDIS_KEY_BLACKLIST_DATA_SP)
    if blacklistSP and len(blacklistSP) > 0:
        blacklistSpData.clear()
        for domain in blacklistSP:
            updateSpData(domain, blacklistSpData)


# 将CIDR表示的IP地址段转换为IP网段数组
# def cidr_to_ip_range(cidr):
#     cidr_parts = cidr.split('/')
#     if len(cidr_parts) != 2:
#         # 在这里处理错误，例如抛出一个自定义的异常或记录错误消息
#         pass
#     else:
#         ip, mask = cidr_parts
#         mask = int(mask)
#         # 计算网络地址
#         network = socket.inet_aton(ip)
#         network = struct.unpack("!I", network)[0] & ((1 << 32 - mask) - 1 << mask)
#         # 计算广播地址
#         broadcast = network | (1 << 32 - mask) - 1
#         # 将地址段转换为元组
#         return (network, broadcast)


# def initBlackList():
#     blacklist = redis_get_map(REDIS_KEY_BLACK_DOMAINS)
#     if blacklist and len(blacklist) > 0:
#         black_list_policy.update(blacklist)

################################################ipv4暂时不能解决根据域名查找ipv4
# # IP地址转换为32位整数
# def ip_to_int(ip):
#     return struct.unpack("!I", socket.inet_aton(ip))[0]
#
#
# def find_ip_range_cache(ip):
#     ip_ranges = ipv4_list_tmp_policy.keys()
#     left, right = 0, len(ip_ranges) - 1
#     while left <= right:
#         mid = (left + right) // 2
#         if ip_ranges[mid][0] <= ip <= ip_ranges[mid][1]:
#             return ip_ranges[mid]
#         elif ip < ip_ranges[mid][0]:
#             right = mid - 1
#         else:
#             left = mid + 1
#     return None
#
# # 二分查找IP网段
# def find_ip_range(ip_ranges, ip):
#     global ipv4_list_tmp_policy
#     left, right = 0, len(ip_ranges) - 1
#     while left <= right:
#         mid = (left + right) // 2
#         if ip_ranges[mid][0] <= ip <= ip_ranges[mid][1]:
#             ipv4_list_tmp_policy[ip_ranges[mid]] = ''
#             ipv4_list_tmp_policy = rank_dict(ipv4_list_tmp_policy)
#             return ip_ranges[mid]
#         elif ip < ip_ranges[mid][0]:
#             right = mid - 1
#         else:
#             left = mid + 1
#     return None

# def rank_dict(dict_orign):
#     # 使用heapq将字典的键按照从小到大的顺序排序
#     sorted_keys = heapq.nsmallest(len(dict_orign), dict_orign.keys())
#     # 构造排序后的字典
#     sorted_data = {key: dict_orign[key] for key in sorted_keys}
#     dict_orign.clear()
#     return sorted_data.copy()
#
#
# # 拉取ipv4数据时进行整数数组转换
# def update_ipv4_int_range(ipstr):
#     iprange = cidr_to_ip_range(ipstr)
#     if iprange:
#         IPV4_INT_ARR[iprange] = ''
#
#
# def initIPV4List():
#     ipv4list = redis_get_map(REDIS_KEY_UPDATE_IPV4_LIST_FLAG)
#     if ipv4list and len(ipv4list) > 0:
#         global IPV4_INT_ARR
#         IPV4_INT_ARR.clear()
#         for ipv4 in ipv4list.keys():
#             update_ipv4_int_range(ipv4)
#         # 简单排序
#         # IPV4_INT_ARR = dict(sorted(IPV4_INT_ARR.items(), key=lambda x: x[0]))
#         # 使用heapq将字典的键按照从小到大的顺序排序
#         IPV4_INT_ARR = rank_dict(IPV4_INT_ARR)
#
#
# # 将CIDR表示的IP地址段转换为IP网段数组
# def cidr_to_ip_range(cidr):
#     cidr_parts = cidr.split('/')
#     if len(cidr_parts) != 2:
#         # 在这里处理错误，例如抛出一个自定义的异常或记录错误消息
#         pass
#     else:
#         ip, mask = cidr_parts
#         mask = int(mask)
#         # 计算网络地址
#         network = socket.inet_aton(ip)
#         network = struct.unpack("!I", network)[0] & ((1 << 32 - mask) - 1 << mask)
#         # 计算广播地址
#         broadcast = network | (1 << 32 - mask) - 1
#         # 将地址段转换为元组
#         return (network, broadcast)
################################################ipv4暂时不能解决根据域名查找ipv4

# redis增加和修改
def redis_add(key, value):
    r.set(key, value)


# redis查询
def redis_get(key):
    return r.get(key)


# 定时器似乎影响挺严重的
# 0-数据未更新 1-数据已更新 max-所有服务器都更新完毕(有max个服务器做负载均衡)
REDIS_KEY_UPDATE_WHITE_LIST_FLAG = "updatewhitelistflag"
REDIS_KEY_UPDATE_BLACK_LIST_FLAG = "updateblacklistflag"
REDIS_KEY_UPDATE_THREAD_NUM_FLAG = "updatethreadnumflag"
REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG = "updatechinadnsserverflag"
REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG = "updatechinadnsportflag"
REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG = "updateextradnsserverflag"
REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG = "updateextradnsportflag"
REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG = "updatesimplewhitelistflag"
REDIS_KEY_UPDATE_IPV4_LIST_FLAG = "updateipv4listflag"
REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG = "updatesimpleblacklistflag"
REDIS_KEY_UPDATE_WHITE_LIST_SP_FLAG = "updatewhitelistspflag"
REDIS_KEY_UPDATE_BLACK_LIST_SP_FLAG = "updateblacklistspflag"


# true-拉取更新吧
def needUpdate(redis_key):
    flag = redis_get(redis_key)
    if flag:
        flag = int(flag.decode())
        # 数据没有更新
        if flag == 0:
            return False
        # 服务器全部更新完毕(逻辑不严谨感觉)
        if flag >= 2:
            redis_add(redis_key, 0)
            return False
        # 服务器未全部完成更新(逻辑不严谨，一个服务器的话还能用用)
        else:
            redis_add(redis_key, flag + 1)
            return True
    return False


def init(sleepSecond):
    while True:
        # if needUpdate(REDIS_KEY_UPDATE_WHITE_LIST_FLAG):
        #     initWhiteList()
        # if needUpdate(REDIS_KEY_UPDATE_BLACK_LIST_FLAG):
        #     initBlackList()
        if needUpdate(REDIS_KEY_UPDATE_WHITE_LIST_SP_FLAG):
            initWhiteListSP()
        if needUpdate(REDIS_KEY_UPDATE_BLACK_LIST_SP_FLAG):
            initBlackListSP()
        # if needUpdate(REDIS_KEY_UPDATE_THREAD_NUM_FLAG):
        #     init_threads_num()
        # if needUpdate(REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG):
        #     init_china_dns_server()
        # if needUpdate(REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG):
        #     init_china_dns_port()
        # if needUpdate(REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG):
        #     init_extra_dns_server()
        # if needUpdate(REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG):
        #     init_extra_dns_port()
        if needUpdate(REDIS_KEY_UPDATE_SIMPLE_WHITE_LIST_FLAG):
            initSimpleWhiteList()
        if needUpdate(REDIS_KEY_UPDATE_SIMPLE_BLACK_LIST_FLAG):
            initSimpleBlackList()
        # if needUpdate(REDIS_KEY_UPDATE_IPV4_LIST_FLAG):
        #     initIPV4List()
        openAutoUpdateSimpleWhiteAndBlackList()
        time.sleep(sleepSecond)


REDIS_KEY_FUNCTION_DICT = "functiondict"
# 是否开启自动维护生成简易黑白名单：0-不开启，1-开启
AUTO_GENERATE_SIMPLE_WHITE_AND_BLACK_LIST = '1'


# 检测是否开启自动维护简易黑白名单
def openAutoUpdateSimpleWhiteAndBlackList():
    global AUTO_GENERATE_SIMPLE_WHITE_AND_BLACK_LIST
    dict = redis_get_map(REDIS_KEY_FUNCTION_DICT)
    if dict:
        if 'switch24' in dict.keys():
            AUTO_GENERATE_SIMPLE_WHITE_AND_BLACK_LIST = str(dict['switch24'])
        else:
            return
    else:
        return


def checkAndUpdateSimpleList(isBlack, domain):
    if AUTO_GENERATE_SIMPLE_WHITE_AND_BLACK_LIST == '0':
        return
    if isBlack:
        if not black_list_simple_policy_queue.full():
            black_list_simple_policy_queue.put(domain)
    else:
        if not white_list_simple_nameserver_policy_queue.full():
            white_list_simple_nameserver_policy_queue.put(domain)


# 线程数获取
def init_threads_num():
    global MAXTHREAD
    num = redis_get(REDIS_KEY_THREADS)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 100
            threadsNum[REDIS_KEY_THREADS] = num
            MAXTHREAD = num
        threadsNum[REDIS_KEY_THREADS] = num
        MAXTHREAD = num
    else:
        num = 100
        threadsNum[REDIS_KEY_THREADS] = num
        MAXTHREAD = num


# 中国DNS端口获取
def init_china_dns_port():
    num = redis_get(REDIS_KEY_CHINA_DNS_PORT)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 5336
            chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num
        chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num
    else:
        num = 5336
        chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num


# 外国DNS端口获取
def init_extra_dns_port():
    num = redis_get(REDIS_KEY_EXTRA_DNS_PORT)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 7874
            extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num
        extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num
    else:
        num = 7874
        extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num


# dns并发查询数获取
def init_dns_query_num():
    num = redis_get(REDIS_KEY_DNS_QUERY_NUM)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 150
            dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = num
        dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = num
    else:
        num = 150
        dnsquerynum[REDIS_KEY_DNS_QUERY_NUM] = num
    return num


# dns并发查询数获取
def init_dns_timeout():
    num = redis_get(REDIS_KEY_DNS_TIMEOUT)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 20
            dnstimeout[REDIS_KEY_DNS_TIMEOUT] = num
        dnstimeout[REDIS_KEY_DNS_TIMEOUT] = num
    else:
        num = 20
        dnstimeout[REDIS_KEY_DNS_TIMEOUT] = num
    return num


# 中国DNS服务器获取
def init_china_dns_server():
    num = redis_get(REDIS_KEY_CHINA_DNS_SERVER)
    if num:
        num = num.decode()
        if num == "":
            num = "127.0.0.1"
            chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num
        chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num
    else:
        num = "127.0.0.1"
        chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num


# 外国dns服务器获取
def init_extra_dns_server():
    num = redis_get(REDIS_KEY_EXTRA_DNS_SERVER)
    if num:
        num = num.decode()
        if num == "":
            num = "127.0.0.1"
            extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num
        extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num
    else:
        num = "127.0.0.1"
        extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num


# 定义一个函数，用于接收客户端的DNS请求


def dns_query(data, china_dns_socket, waiguo_dns_socket, china_dns_server, china_port, waiguo_dns_server, waiguo_port):
    # 解析客户端的DNS请求
    if isChinaDomain(data):
        port = china_port
        dns_server = china_dns_server
        sock = china_dns_socket
    else:
        port = waiguo_port
        dns_server = waiguo_dns_server
        sock = waiguo_dns_socket
    # 向DNS服务器发送请求
    try:
        sock.sendto(data, (dns_server, port))
        # 接收DNS服务器的响应
        response, addr = sock.recvfrom(1024)
        # 返回响应给客户端
        return response
    except socket.error as e:
        print(f'dns_query error: {e}')
        return ''


# 定义可调用对象
def handle_request(sock, executor, china_dns_socket, waiguo_dns_socket, china_dns_server, china_port, waiguo_dns_server,
                   waiguo_port):
    # 接收DNS请求
    try:
        data, addr = sock.recvfrom(1024)
        # 异步调用dns_query函数
        response = executor.submit(dns_query, data, china_dns_socket, waiguo_dns_socket, china_dns_server, china_port,
                                   waiguo_dns_server,
                                   waiguo_port)
        # # 发送DNS响应
        sock.sendto(response.result(), addr)
    except socket.error as e:
        print(f'handle_request error: {e}')
        pass


# redis存储map字典，字典主键唯一，重复主键只会复写
def redis_add_map(key, my_dict):
    r.hmset(key, my_dict)


def main():
    init_threads_num()
    init_china_dns_server()
    init_china_dns_port()
    init_extra_dns_server()
    init_extra_dns_port()
    init_dns_query_num()
    init_dns_timeout()
    initWhiteListSP()
    initBlackListSP()
    # initIPV4List()
    initSimpleWhiteList()
    initSimpleBlackList()
    timer_thread1 = threading.Thread(target=init, args=(60,), daemon=True)
    timer_thread1.start()
    timer_thread2 = threading.Thread(target=deal_black_list_simple_policy_queue,
                                     args=(10,), daemon=True)
    timer_thread2.start()
    timer_thread3 = threading.Thread(target=clearCache,
                                     args=(86400,), daemon=True)
    timer_thread3.start()
    timer_thread4 = threading.Thread(target=deal_black_list_simple_tmp_cache_queue,
                                     args=(10,), daemon=True)
    timer_thread4.start()
    timer_thread5 = threading.Thread(target=deal_black_list_simple_tmp_policy_queue,
                                     args=(10,), daemon=True)
    timer_thread5.start()
    timer_thread6 = threading.Thread(target=deal_white_list_simple_tmp_cache_queue,
                                     args=(10,), daemon=True)
    timer_thread6.start()
    timer_thread7 = threading.Thread(target=deal_white_list_simple_tmp_policy_queue,
                                     args=(10,), daemon=True)
    timer_thread7.start()
    timer_thread8 = threading.Thread(target=deal_black_list_tmp_cache_queue,
                                     args=(10,), daemon=True)
    timer_thread8.start()
    timer_thread9 = threading.Thread(target=deal_black_list_tmp_policy_queue,
                                     args=(10,), daemon=True)
    timer_thread9.start()
    timer_thread10 = threading.Thread(target=deal_white_list_tmp_cache_queue,
                                      args=(10,), daemon=True)
    timer_thread10.start()
    timer_thread11 = threading.Thread(target=deal_white_list_tmp_policy_queue,
                                      args=(10,), daemon=True)
    timer_thread11.start()
    timer_thread12 = threading.Thread(target=clearCacheFast,
                                      args=(3613,), daemon=True)
    timer_thread12.start()
    # 中国dns端口
    china_port = chinadnsport[REDIS_KEY_CHINA_DNS_PORT]
    # 中国dns服务器
    china_dns_server = chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER]
    # 外国dns端口
    waiguo_port = extradnsport[REDIS_KEY_EXTRA_DNS_PORT]
    # 外国dns服务器
    waiguo_dns_server = extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER]
    # 并发消息数
    message_num = dnsquerynum[REDIS_KEY_DNS_QUERY_NUM]
    # 通信过期时间
    timeout = dnstimeout[REDIS_KEY_DNS_TIMEOUT]
    # 开始接收客户端的DNS请求
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0', 22770))  # 22770  53
        # 设置等待时长为30s
        sock.settimeout(timeout)
        # 创建一个UDP socket
        try:
            # 开始接收客户端的DNS请求
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as china_dns_socket:
                china_dns_socket.connect((china_dns_server, china_port))
                china_dns_socket.settimeout(timeout)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as waiguo_dns_socket:
                    waiguo_dns_socket.connect((waiguo_dns_server, waiguo_port))
                    waiguo_dns_socket.settimeout(timeout)
                    try:
                        # 创建一个线程池对象
                        with concurrent.futures.ThreadPoolExecutor(max_workers=message_num) as executor:
                            while True:
                                try:
                                    handle_request(sock, executor, china_dns_socket, waiguo_dns_socket,
                                                   china_dns_server,
                                                   china_port, waiguo_dns_server, waiguo_port)
                                except:
                                    pass
                    except:
                        pass
        except socket.error as e:
            print(f'socket error: {e}')
        except:
            pass


# 考虑过线程池或者负载均衡，线程池需要多个端口不大合适，负载均衡似乎不错，但有点复杂，后期看看22770
if __name__ == '__main__':
    start = False
    while True:
        try:
            # 检查Redis连接状态
            r.ping()
            print('!!!!!!!!!!!!!!!!!!!!!!!Redis is ready dns.py\n')
            start = True
            break
        except redis.ConnectionError:
            # 连接失败，等待一段时间后重试
            time.sleep(1)
    if start:
        main()

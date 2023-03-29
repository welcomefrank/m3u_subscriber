import concurrent.futures
import math
import socket
import threading
import time
import dnslib
import redis
import ipaddress

r = redis.Redis(host='localhost', port=6379)
# 白名单总命中缓存规则，数据中等，是实际命中的规则缓存
white_list_tmp_policy = {}
# 白名单总命中缓存，数据最少，是实际访问的域名缓存
white_list_tmp_cache = {}
# 未知域名访问缓存记录
unkown_list_tmp_cache = {}
# 下载的域名白名单存储到redis服务器里
REDIS_KEY_WHITE_DOMAINS = "whitedomains"
# 下载的域名黑名单存储到redis服务器里
REDIS_KEY_BLACK_DOMAINS = "blackdomains"
# 黑名单总命中缓存规则，数据中等，是实际命中的规则缓存
black_list_tmp_policy = {}
# 黑名单总命中缓存，数据最少，是实际访问的域名缓存
black_list_tmp_cache = {}
white_list_nameserver_policy = {}
black_list_policy = {}
ipv4_list = {}

ipv4_list_tmp_cache = {}
ipv4_list_tmp_policy = {}

ipCheckDomian = ["ip.skk.moe", "ip.swcdn.skk.moe", "api.ipify.org",
                 "api-ipv4.ip.sb", "d.skk.moe", "qqwry.api.skk.moe",
                 "ipinfo.io", "cdn.ipinfo.io", "ip.sb",
                 "ip-api.com", "browserleaks.com", "www.dnsleaktest.com"]

# 规则：先查unkown_list_tmp_cache，有的话转发5335,
# 没有再查black_list_tmp_cache，有记录直接转发5335,
# 没有再查white_list_tmp_cache,有记录直接转发5336，
# 没有再查black_list_tmp_policy,命中则更新black_list_tmp_cache，转发5335。
# 没有则查white_list_tmp_policy,命中则更新white_list_tmp_cache，转发5336。
# 没有命中则black_list_policy，查到则更新black_list_tmp_policy，blacl_list_tmp_cache，再转发5335
# 没有命中则white_list_nameserver_policy，查到则更新white_list_tmp_policy，white_list_tmp_cache，再转发5336
# 没有命中则更新unkown_list_tmp_cache，转发给127.0.0.1#5335

HOST_IP = "0.0.0.0"

# 并发检测白名单黑名单线程数主键
REDIS_KEY_THREADS = "threadsnum"
threadsNum = {REDIS_KEY_THREADS: 100}

# 中国DNS服务器主键
REDIS_KEY_CHINA_DNS_SERVER = "chinadnsserver"
chinadnsserver = {REDIS_KEY_CHINA_DNS_SERVER: "127.0.0.1"}

# 中国DNS端口主键
REDIS_KEY_CHINA_DNS_PORT = "chinadnsport"
chinadnsport = {REDIS_KEY_CHINA_DNS_PORT: 5336}

# 外国DNS服务器主键
REDIS_KEY_EXTRA_DNS_SERVER = "extradnsserver"
extradnsserver = {REDIS_KEY_EXTRA_DNS_SERVER: "127.0.0.1"}

# 外国DNS端口主键
REDIS_KEY_EXTRA_DNS_PORT = "extradnsport"
extradnsport = {REDIS_KEY_EXTRA_DNS_PORT: 7874}


# 获取软路由主路由ip
def getMasterIp():
    # 获取宿主机IP地址
    host_ip = socket.gethostbyname(socket.gethostname())
    # client = docker.from_env()
    # # 设置要创建容器的参数
    # container_name = 'my_container_name'
    # image_name = 'my_image_name'
    # command = 'python /path/to/my_script.py'
    # volumes = {'/path/on/host': {'bind': '/path/on/container', 'mode': 'rw'}}
    # ports = {'8080/tcp': ('0.0.0.0', 8080)}
    #
    # # 获取宿主机IP地址
    # host_ip = socket.gethostbyname(socket.gethostname())
    #
    # # 设置容器的host_config属性
    # host_config = client.api.create_host_config(
    #     network_mode='host',  # 使用宿主机的网络模式
    #     extra_hosts={'host.docker.internal': host_ip}  # 添加一个docker内部host和宿主机IP的映射
    # )
    #
    # # 创建容器
    # container = client.containers.create(
    #     name=container_name,
    #     image=image_name,
    #     command=command,
    #     volumes=volumes,
    #     ports=ports,
    #     host_config=host_config
    # )
    #
    # # 启动容器
    # container.start()
    return host_ip


# 检测域名是否在记录的黑名单域名策略缓存  是-true  不是-false
def inBlackListPolicyCache(domain_name_str):
    # 在今日已经命中的规则里查找
    for vistedDomain in black_list_tmp_policy.keys():
        # 新域名在规则里有类似域名，更新black_list_tmp_cache
        if vistedDomain in domain_name_str:
            black_list_tmp_cache[domain_name_str] = ""
            return True
        # 缓存域名在新域名里有匹配
        if domain_name_str in vistedDomain:
            black_list_tmp_cache[domain_name_str] = ""
            return True
    return False


# 检测域名是否在记录的黑名单域名缓存  是-true  不是-false
def inBlackListCache(domain_name_str):
    for recordThiteDomain in black_list_tmp_cache.keys():
        # 新域名在缓存里有类似域名
        if recordThiteDomain in domain_name_str:
            return True
        # # 缓存域名在新域名里有匹配
        if domain_name_str in recordThiteDomain:
            return True
    return False


# 检测域名是否在未知缓存里，是-True,不是-False
def inUnkownCache(domain_name_str):
    # 命中未知域名缓存，直接丢给5335
    for unkown in unkown_list_tmp_cache.keys():
        # 新域名在缓存里有类似域名
        if unkown in domain_name_str:
            return True
        # 缓存域名在新域名里有匹配
        if domain_name_str in unkown:
            return True
    return False


# 检测域名是否在记录的白名单域名缓存  是-true  不是-false
def inWhiteListCache(domain_name_str):
    for recordThiteDomain in white_list_tmp_cache.keys():
        # 新域名在缓存里有类似域名
        if recordThiteDomain in domain_name_str:
            return True
        # # 缓存域名在新域名里有匹配
        if domain_name_str in recordThiteDomain:
            return True
    return False


# 检测域名是否在记录的白名单域名策略缓存  是-true  不是-false
def inWhiteListPolicyCache(domain_name_str):
    # 在今日已经命中的规则里查找
    for vistedDomain in white_list_tmp_policy.keys():
        # 新域名在规则里有类似域名，更新white_list_tmp_cache
        if vistedDomain in domain_name_str:
            white_list_tmp_cache[domain_name_str] = ""
            return True
        # 缓存域名在新域名里有匹配
        if domain_name_str in vistedDomain:
            white_list_tmp_cache[domain_name_str] = ""
            return True
    return False


def check_domain_inIpv4ListPolicy(ip, ipv4_list_chunk):
    for key in ipv4_list_chunk:
        if ip in ipaddress.IPv4Network(key):
            ipv4_list_tmp_cache[ip] = ""
            ipv4_list_tmp_policy[key] = ""
            return True


# 判断域名ip是否归属中国大陆
def is_china_domain(domain):
    # 解析域名为IP地址
    try:
        ip_address = ipaddress.IPv4Address(socket.gethostbyname(domain))
    except socket.gaierror:
        return False
    # 判断IP地址是否是私有IP地址
    if ip_address.is_private:
        return False
    if len(ipv4_list) == 0:
        initIpv4List()
    # 判断IP地址是否在中国大陆IP段中
    maxThread = 100
    items = sorted(ipv4_list.keys())
    length = len(items)
    # 计算每个线程处理的数据大小
    chunk_size = math.ceil(length / maxThread)
    with concurrent.futures.ThreadPoolExecutor(max_workers=maxThread) as executor:
        futures = []
        for i in range(maxThread):
            start_index = i * chunk_size
            end_index = min(start_index + chunk_size, length)
            black_list_chunk = items[start_index:end_index]
            future = executor.submit(check_domain_inIpv4ListPolicy, black_list_chunk)
            futures.append(future)
            if future.result():
                return True
        return False


# 检测域名是否在全部黑名单域名策略  是-true  不是-false
def inBlackListPolicy(domain_name_str):
    if len(black_list_policy) == 0:
        initBlackList()
    if black_list_policy:
        if len(black_list_policy) == 0:
            return False
        thik = stupidThink(domain_name_str)
        for thinkDomain in thik:
            maxThread = 100
            items = sorted(black_list_policy.keys())
            length = len(items)
            # 计算每个线程处理的数据大小
            chunk_size = math.ceil(length / maxThread)
            with concurrent.futures.ThreadPoolExecutor(max_workers=maxThread) as executor:
                futures = []
                for i in range(maxThread):
                    start_index = i * chunk_size
                    end_index = min(start_index + chunk_size, length)
                    black_list_chunk = items[start_index:end_index]
                    future = executor.submit(check_domain_inBlackListPolicy, thinkDomain, black_list_chunk)
                    futures.append(future)
                    if future.result():
                        return True
        return False

    else:
        return False


def check_domain_inBlackListPolicy(domain_name_str, black_list_chunk):
    for key in black_list_chunk:
        # 缓存域名在新域名里有匹配
        if domain_name_str in key:
            black_list_tmp_cache[domain_name_str] = ""
            black_list_tmp_policy[key] = ""
            return True


# 检测域名是否在全部白名单域名策略  是-true  不是-false
def inWhiteListPolicy(domain_name_str):
    if len(white_list_nameserver_policy) == 0:
        initWhiteList()
    if white_list_nameserver_policy:
        if len(white_list_nameserver_policy) == 0:
            return False
        thik = stupidThink(domain_name_str)
        for thinkDomain in thik:
            maxThread = 100
            items = sorted(white_list_nameserver_policy.keys())
            length = len(items)
            # 计算每个线程处理的数据大小
            chunk_size = math.ceil(length / maxThread)
            with concurrent.futures.ThreadPoolExecutor(max_workers=maxThread) as executor:
                futures = []
                for i in range(0, maxThread):
                    start_index = i * chunk_size
                    end_index = min(start_index + chunk_size, length)
                    white_list_chunk = items[start_index:end_index]
                    future = executor.submit(check_domain_inWhiteListPolicy, thinkDomain, white_list_chunk)
                    futures.append(future)
                    if future.result():
                        return True
        return False

    else:
        return False


def check_domain_inWhiteListPolicy(domain_name_str, white_list_chunk):
    for key in white_list_chunk:
        # 新域名在全部规则里有类似域名，更新whiteDomainPolicy
        if domain_name_str in key:
            white_list_tmp_cache[domain_name_str] = ""
            white_list_tmp_policy[key] = ""
            return True
    return False


def stupidThink(domain_name):
    sub_domains = []
    for i in range(len(domain_name.split('.')) - 1):
        sub_domains.append('.'.join(domain_name.split('.')[i:]))
    return sub_domains


# 白名单中国大陆IPV4下载数据
REDIS_KEY_WHITELIST_IPV4_DATA = "whitelistipv4data"


# 是中国域名   是-true  不是-false
def isChinaDomain(data):
    dns_msg = dnslib.DNSRecord.parse(data)
    domain_name = dns_msg.q.qname
    domain_name_str = str(domain_name)
    domain_name_str = domain_name_str[:-1]
    if domain_name_str in ipCheckDomian:
        return False
    if domain_name_str.endswith(".cn") or domain_name_str.endswith(".中国"):
        return True
    # 在已经命中的外国域名查找，直接丢给5335
    if inBlackListCache(domain_name_str):
        return False
    # 在今日已经命中的黑名单规则里查找
    if inBlackListPolicyCache(domain_name_str):
        return False
    # 黑名单规则里查找
    if inBlackListPolicy(domain_name_str):
        return False
    # 在已经命中的中国域名查找，直接丢给5336
    if inWhiteListCache(domain_name_str):
        return True
    # 在今日已经命中的白名单规则里查找
    if inWhiteListPolicyCache(domain_name_str):
        return True
    # 在全部白名单规则里查找
    if inWhiteListPolicy(domain_name_str):
        return True
    # # 命中未知域名缓存，直接丢给5335
    # if inUnkownCache(domain_name_str):
    #     return False
    # unkown_list_tmp_cache[domain_name_str] = ""

    # if is_china_domain(domain_name_str):
    #     white_list_tmp_cache[domain_name_str] = ""
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


def initWhiteList():
    whitelist = redis_get_map(REDIS_KEY_WHITE_DOMAINS)
    if whitelist and len(whitelist) > 0:
        white_list_nameserver_policy.update(whitelist)


def initBlackList():
    blacklist = redis_get_map(REDIS_KEY_BLACK_DOMAINS)
    if blacklist and len(blacklist) > 0:
        black_list_policy.update(blacklist)


def initIpv4List():
    ipv4list = redis_get_map(REDIS_KEY_WHITELIST_IPV4_DATA)
    if ipv4list and len(ipv4list) > 0:
        ipv4_list.update(ipv4list)


# redis增加和修改
def redis_add(key, value):
    r.set(key, value)


# redis查询
def redis_get(key):
    return r.get(key)


# 0-数据未更新 1-数据已更新 max-所有服务器都更新完毕(有max个服务器做负载均衡)
REDIS_KEY_UPDATE_WHITE_LIST_FLAG = "updatewhitelistflag"
REDIS_KEY_UPDATE_BLACK_LIST_FLAG = "updateblacklistflag"
REDIS_KEY_UPDATE_IPV4_LIST_FLAG = "updateipv4listflag"
REDIS_KEY_UPDATE_THREAD_NUM_FLAG = "updatethreadnumflag"
REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG = "updatechinadnsserverflag"
REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG = "updatechinadnsportflag"
REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG = "updateextradnsserverflag"
REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG = "updateextradnsportflag"


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
        if needUpdate(REDIS_KEY_UPDATE_WHITE_LIST_FLAG):
            initWhiteList()
        if needUpdate(REDIS_KEY_UPDATE_BLACK_LIST_FLAG):
            initBlackList()
        # if needUpdate(REDIS_KEY_UPDATE_IPV4_LIST_FLAG):
        #     initIpv4List()
        if needUpdate(REDIS_KEY_UPDATE_THREAD_NUM_FLAG):
            init_threads_num()
        if needUpdate(REDIS_KEY_UPDATE_CHINA_DNS_SERVER_FLAG):
            init_china_dns_server()
        if needUpdate(REDIS_KEY_UPDATE_CHINA_DNS_PORT_FLAG):
            init_china_dns_port()
        if needUpdate(REDIS_KEY_UPDATE_EXTRA_DNS_SERVER_FLAG):
            init_extra_dns_server()
        if needUpdate(REDIS_KEY_UPDATE_EXTRA_DNS_PORT_FLAG):
            init_extra_dns_port()
        time.sleep(sleepSecond)


# 定义一个函数，用于接收客户端的DNS请求


def dns_query(data):
    # 解析客户端的DNS请求
    # domain_name = data[2:-5].decode('utf-8')
    # simple_domain_name = simpleDomain(domain_name)
    if isChinaDomain(data):
        # 5336-大陆，测试是桥接模式可以被寻址路由
        # port = 5336
        port = chinadnsport[REDIS_KEY_CHINA_DNS_PORT]
        dns_server = chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER]
        # dns_server = '114.114.114.114'
        # dns_server = '192.168.5.95'
    else:
        # 外国5335/7874,测试应该是桥接模式可以被寻址路由，host模式和插件的adguardhome直接放弃使用
        # 桥接模式
        # dns_server = '192.168.5.1'
        port = extradnsport[REDIS_KEY_EXTRA_DNS_PORT]
        dns_server = extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER]
        # port = 7874
    # 随机选择一个DNS服务器openwrt，host模式
    #dns_server = '127.0.0.1'
    # 电脑测试，实际上openwrt也只能使用这个，也就是软路由lan口，127.0.0.1完全没有用，妈的
    # docker的dns似乎无法到达，只能是插件
    # dns_server = '192.168.5.1'
    # dns_server = HOST_IP
    # 向DNS服务器发送请求
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(15)
    sock.sendto(data, (dns_server, port))
    # 接收DNS服务器的响应
    response, addr = sock.recvfrom(4096)
    sock.close()
    # 返回响应给客户端
    return response


# 线程数获取
def init_threads_num():
    num = redis_get(REDIS_KEY_THREADS)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 100
            redis_add(REDIS_KEY_THREADS, num)
            threadsNum[REDIS_KEY_THREADS] = num
        threadsNum[REDIS_KEY_THREADS] = num
    else:
        num = 100
        redis_add(REDIS_KEY_THREADS, num)
        threadsNum[REDIS_KEY_THREADS] = num


# 中国DNS端口获取
def init_china_dns_port():
    num = redis_get(REDIS_KEY_CHINA_DNS_PORT)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 5336
            redis_add(REDIS_KEY_CHINA_DNS_PORT, num)
            chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num
        chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num
    else:
        num = 5336
        redis_add(REDIS_KEY_CHINA_DNS_PORT, num)
        chinadnsport[REDIS_KEY_CHINA_DNS_PORT] = num


# 外国DNS端口获取
def init_extra_dns_port():
    num = redis_get(REDIS_KEY_EXTRA_DNS_PORT)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 7874
            redis_add(REDIS_KEY_EXTRA_DNS_PORT, num)
            extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num
        extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num
    else:
        num = 7874
        redis_add(REDIS_KEY_EXTRA_DNS_PORT, num)
        extradnsport[REDIS_KEY_EXTRA_DNS_PORT] = num


# 中国DNS服务器获取
def init_china_dns_server():
    num = redis_get(REDIS_KEY_CHINA_DNS_SERVER)
    if num:
        num = num.decode()
        if num == "":
            num = "127.0.0.1"
            redis_add(REDIS_KEY_CHINA_DNS_SERVER, num)
            chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num
        chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num
    else:
        num = "127.0.0.1"
        redis_add(REDIS_KEY_CHINA_DNS_SERVER, num)
        chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER] = num


# 外国dns服务器获取
def init_extra_dns_server():
    num = redis_get(REDIS_KEY_EXTRA_DNS_SERVER)
    if num:
        num = num.decode()
        if num == "":
            num = "127.0.0.1"
            redis_add(REDIS_KEY_EXTRA_DNS_SERVER, num)
            extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num
        extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num
    else:
        num = "127.0.0.1"
        redis_add(REDIS_KEY_EXTRA_DNS_SERVER, num)
        extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER] = num


# 考虑过线程池或者负载均衡，线程池需要多个端口不大合适，负载均衡似乎不错，但有点复杂，后期看看
if __name__ == '__main__':
    init_threads_num()
    init_china_dns_server()
    init_china_dns_port()
    init_extra_dns_server()
    init_extra_dns_port()
    # HOST_IP = getMasterIp()
    timer_thread1 = threading.Thread(target=init, args=(10,))
    timer_thread1.start()
    # 创建一个UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # # 软路由模式
        # if HOST_IP == "192.168.5.1" or HOST_IP == "127.0.0.1":
        #     port = 5911
        # # 电脑模式
        # else:
        #     port = 53
        # 绑定本地的IP和端口
        # sock.bind(('', 5911))
        # 电脑监听测试,127.0.0.1是容器内部网络环境
        sock.bind(('0.0.0.0', 5911))
        # openwrt监听
        # sock.bind(('0.0.0.0', 5911))
        # 设置等待时长为30s,这种很难超时
        sock.settimeout(18)
        # 开始接收客户端的DNS请求
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                response = dns_query(data)
                sock.sendto(response, addr)
            except:
                pass
    except:
        pass
    finally:
        sock.close()
        timer_thread1.join()

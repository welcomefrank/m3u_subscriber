import concurrent.futures
import math
import socket
import threading
import time
import dnslib
import redis

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

# china   api.ttt.sh
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


# redis增加和修改
def redis_add(key, value):
    r.set(key, value)


# redis查询
def redis_get(key):
    return r.get(key)


# 0-数据未更新 1-数据已更新 max-所有服务器都更新完毕(有max个服务器做负载均衡)
REDIS_KEY_UPDATE_WHITE_LIST_FLAG = "updatewhitelistflag"
REDIS_KEY_UPDATE_BLACK_LIST_FLAG = "updateblacklistflag"
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


# 线程数获取
def init_threads_num():
    num = redis_get(REDIS_KEY_THREADS)
    if num:
        num = int(num.decode())
        if num == 0:
            num = 100
            threadsNum[REDIS_KEY_THREADS] = num
        threadsNum[REDIS_KEY_THREADS] = num
    else:
        num = 100
        threadsNum[REDIS_KEY_THREADS] = num


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


def dns_query(data):
    # 解析客户端的DNS请求
    if isChinaDomain(data):
        port = chinadnsport[REDIS_KEY_CHINA_DNS_PORT]
        dns_server = chinadnsserver[REDIS_KEY_CHINA_DNS_SERVER]
    else:
        port = extradnsport[REDIS_KEY_EXTRA_DNS_PORT]
        dns_server = extradnsserver[REDIS_KEY_EXTRA_DNS_SERVER]
    # 向DNS服务器发送请求
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(58)
        sock.sendto(data, (dns_server, port))
        # 接收DNS服务器的响应
        response, addr = sock.recvfrom(4096)
        sock.close()
        # 返回响应给客户端
        return response
    except socket.error as e:
        print(f'dns_query error: {e}')
        return ''


# 定义可调用对象
def handle_request(sock, executor):
    # 接收DNS请求
    try:
        data, addr = sock.recvfrom(4096)
        # 异步调用dns_query函数
        response = executor.submit(dns_query, data)
        # 发送DNS响应
        sock.sendto(response.result(), addr)
    except socket.error as e:
        print(f'handle_request error: {e}')


def main():
    init_threads_num()
    init_china_dns_server()
    init_china_dns_port()
    init_extra_dns_server()
    init_extra_dns_port()
    timer_thread1 = threading.Thread(target=init, args=(10,), daemon=True)
    timer_thread1.start()
    try:
        # 创建一个线程池对象
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            # 创建一个UDP socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('0.0.0.0', 22770))
                # 设置等待时长为30s
                sock.settimeout(60)
                # 开始接收客户端的DNS请求
                try:
                    while True:
                        try:
                            handle_request(sock, executor)
                        except:
                            pass
                except:
                    pass
                finally:
                    sock.close()
            except socket.error as e:
                print(f'socket error: {e}')
    except:
        pass


# 考虑过线程池或者负载均衡，线程池需要多个端口不大合适，负载均衡似乎不错，但有点复杂，后期看看22770
if __name__ == '__main__':
    start = False
    while True:
        # 检查Redis连接状态
        if not r.ping():
            # 关闭旧连接
            r.close()
            # 创建新的Redis连接
            r = redis.Redis(host='localhost', port=6379)
            print('!!!!!!!!!!!!!!!!!!!!!!!Redis is not ready dns.py\n')
        else:
            print('!!!!!!!!!!!!!!!!!!!!!!!Redis is ready dns.py\n')
            start = True
            break
    if start:
        main()

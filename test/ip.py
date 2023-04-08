# IP地址转换为32位整数
import socket
import struct


# 判断ip是否在网段里面


# 二分查找IP网段
def find_ip_range(ip_ranges, ip):
    left, right = 0, len(ip_ranges) - 1
    while left <= right:
        mid = (left + right) // 2
        if ip_ranges[mid][0] <= ip <= ip_ranges[mid][1]:
            return ip_ranges[mid]
        elif ip < ip_ranges[mid][0]:
            right = mid - 1
        else:
            left = mid + 1
    return None


# 检测域名是否属于IP网段数组范围
def check_domain_in_ip_range(ip_ranges, domain):
    ip = ip_to_int(socket.gethostbyname(domain))
    ip_range = find_ip_range(ip_ranges, ip)
    return ip_range is not None


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

# 将CIDR表示的IP地址段转换为IP网段数组
def cidr_to_ip_range(cidr):
    ip, mask = cidr.split('/')
    mask = int(mask)
    # 计算网络地址
    network = socket.inet_aton(ip)
    network = struct.unpack("!I", network)[0] & ((1 << 32 - mask) - 1 << mask)
    # 计算广播地址
    broadcast = network | (1 << 32 - mask) - 1
    # 将地址段转换为元组
    return (network, broadcast)


if __name__ == '__main__':
    # IP网段数组
    ip_ranges = [
        (ip_to_int("192.168.1.0"), ip_to_int("192.168.1.255")),
        (ip_to_int("192.168.2.0"), ip_to_int("192.168.2.255")),
        (ip_to_int("10.0.0.0"), ip_to_int("10.255.255.255")),
    ]

    # 检测域名
    domain = "www.google.com"
    if check_domain_in_ip_range(ip_ranges, domain):
        print("{0} belongs to IP range".format(domain))
    else:
        print("1" in "1")
        print("{0} does not belong to IP range".format(domain))

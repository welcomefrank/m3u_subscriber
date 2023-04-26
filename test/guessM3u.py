import socket


def find_live_streams(ip_address, port_range):
    """
    根据给定的IP地址和端口范围查找直播源
    """
    global sock
    live_streams = []
    for port in range(port_range[0], port_range[1] + 1):
        address = (ip_address, port)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(address)
            if result == 0:
                # 连接成功，将地址添加到直播流列表中
                stream_address = f"http://{ip_address}:{8888}/udp/239.77.0.173:{port}"
                live_streams.append(stream_address)
        except:
            pass
        finally:
            sock.close()

    return live_streams

if __name__ == '__main__':
    list=find_live_streams('www.kitcc.cn', [5100,5200])
    print(list)
import os
import socket
import threading


# 局域网文字图像视频嗅探

def handle_client(client_socket, address):
    try:
        # 读取请求头
        data = client_socket.recv(1024)
        request = data.decode('utf-8')

        # 获取请求方法、路径和协议版本
        request_method = request.split(' ')[0]
        request_path = request.split(' ')[1]
        request_protocol = request.split(' ')[2]

        # 判断请求方法是否为 GET
        if request_method == 'GET':
            # 判断请求的文件类型
            if request_path.endswith('.jpg') or request_path.endswith('.png'):
                print('This is an image file')
                # 保存图像文件到本地
                with open(os.path.basename(request_path), 'wb') as f:
                    while True:
                        file_data = client_socket.recv(1024)
                        if not file_data:
                            break
                        f.write(file_data)
            elif request_path.endswith('.mp4') or request_path.endswith('.avi'):
                print('This is a video file')
                # 保存视频文件到本地
                with open(os.path.basename(request_path), 'wb') as f:
                    while True:
                        file_data = client_socket.recv(1024)
                        if not file_data:
                            break
                        f.write(file_data)
            else:
                print('This is a text file')
                # 保存文本文件到本地
                with open(os.path.basename(request_path), 'w') as f:
                    while True:
                        file_data = client_socket.recv(1024)
                        if not file_data:
                            break
                        f.write(file_data.decode('utf-8'))

        else:
            print('Unsupported request method')

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建套接字
    server_socket.bind(('0.0.0.0', 80))
    server_socket.listen(5)

    try:
        while True:
            (client_socket, address) = server_socket.accept()  # 等待客户端连接
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
            client_thread.start()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server_socket.close()


if __name__ == '__main__':
    print("1" in "1")
    start_server()


import multiprocessing
import os
import requests
import sqlite3
import threading
import time
import json
import re
from flask import Flask, jsonify, request, send_file

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

DATABASE = 'urls.db'


# Create table in database if it doesn't exist
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS items
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        value TEXT DEFAULT '')''')
    conn.commit()
    # 关闭数据库连接
    cursor.close()
    conn.close()


def download_and_process_m3u_file(url):
    try:
        # Download the M3U file from the specified URL
        response = requests.get(url)
        m3u_string = response.text
        # Remove the "#EXTM3U" header from the M3U string
        m3u_string = m3u_string.replace("#EXTM3U", "")
        m3u_string += "\n"
        return m3u_string
    except:
        return ""


# 写入最终的m3u文件
def write_m3u(urls):
    if os.path.exists("/A.m3u"):
        os.remove("/A.m3u")
    with open("/A.m3u", 'w', encoding='utf-8') as f:
        for url in urls:
            f.write(url)


def download_files(urls):
    pool = multiprocessing.Pool(processes=len(urls))
    results = pool.map(download_and_process_m3u_file, urls)
    pool.close()
    pool.join()
    return "".join(results)


# Add an item to the database
def add_item(name, value):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items")
    items = cursor.fetchall()
    for item in items:
        if item[1] == name:
            # 关闭数据库连接
            cursor.close()
            conn.close()
            return
    cursor.execute("INSERT INTO items (name, value) VALUES (?, ?)", (name, value))
    conn.commit()
    # 关闭数据库连接
    cursor.close()
    conn.close()


# 定时器每隔半小时自动刷新订阅列表
def timer_func():
    while True:
        chaoronghe()
        time.sleep(1800)  # 等待30min


# Delete an item from the database
def delete_item(url):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM items WHERE name = ?", (url,))
    conn.commit()
    # 关闭数据库连接
    cursor.close()
    conn.close()


@app.route('/addnewm3u', methods=['POST'])
def addnewm3u():
    # 获取 HTML 页面发送的 POST 请求参数
    addurl = request.json.get('addurl')
    name = request.json.get('name')
    add_item(addurl, name)
    return jsonify({'addresult': "add success"})


@app.route('/deletewm3u', methods=['POST'])
def deletewm3u():
    # 获取 HTML 页面发送的 POST 请求参数
    deleteurl = request.json.get('deleteurl')
    delete_item(deleteurl)
    return jsonify({'deleteresult': "delete success"})


# Get all items from the database
@app.route('/getall', methods=['GET'])
def getall():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items")
    items = cursor.fetchall()
    # 关闭数据库连接
    cursor.close()
    conn.close()
    # 返回表的全部数据
    return jsonify(items)


@app.route('/process_m3u', methods=['POST'])
def process_m3u():
    # 获取 HTML 页面发送的 POST 请求参数
    m3u_urls = request.json.get('m3u_urls')
    # m3u_urls = "https://raw.githubusercontent.com/liudaoguiguzi/ppap/main/1.m3u"
    if m3u_urls is None:
        return jsonify({'message': 'Missing input string parameter'})
    else:
        my_array = m3u_urls.split("\n")
        result = download_files(my_array)
        write_m3u(result)
        return jsonify({'message': result})


# 全部订阅链接超融合
@app.route('/chaoronghe', methods=['GET'])
def chaoronghe():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items")
    items = cursor.fetchall()
    # 关闭数据库连接
    cursor.close()
    conn.close()
    my_array = ""
    for item in items:
        my_array += item[1] + "\n"
    if len(my_array) == 0:
        return 'empty'
    result = download_files(my_array.split("\n"))
    # 格式优化
    new_content = formatTxt(result.split("\n"))
    # 格式优化
    write_m3u(new_content)
    return "result"


def formatTxt(data):
    new_content = ""
    defalutname = "佚名"
    tmpurl = []
    for i in range(len(data)):
        line = data[i].strip()
        if line == "":
            continue
        # 假定直播名字和直播源不在同一行
        if line.encode().startswith(b"#EXTINF"):
            continue
        # 不是http开头，可能是直播源
        if not line.encode().startswith(b"http"):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,http", line):
                name, url = line.split(",", 1)
                if url in tmpurl:
                    continue
                tmpurl.append(url)
                if name:
                    new_content += f'#EXTINF:-1 tvg-name="{name}"\n{url}\n'
                else:
                    new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{url}\n'
            # 匹配:不是直播源和频道
            else:
                new_content += line + "\n"
        # http开始
        else:
            # 去重复
            if line in tmpurl:
                continue
            # index=0
            if i == 0:
                new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{line}\n'
                tmpurl.append(line)
                continue
            preline = data[i - 1].strip()
            # 没有名字
            if preline == "":
                new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{line}\n'
                tmpurl.append(line)
                continue
            # 不是名字
            if not preline.encode().startswith(b"#EXTINF"):
                new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{line}\n'
                tmpurl.append(line)
                continue
            # 有名字
            else:
                new_content += f'{preline}\n{line}\n'
                tmpurl.append(line)
                continue
    return new_content


# 数据库全部数据转json字符串
def generate_json_string():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items")
    items = cursor.fetchall()
    # 关闭数据库连接
    cursor.close()
    conn.close()
    # 将查询结果转换为字典
    json_dict = {"data": []}
    for row in items:
        json_dict['data'].append({
            "link": row[1],
            "tag": row[2],
        })
    json_str = json.dumps(json_dict)
    return json_str


@app.route('/download_json_file', methods=['GET'])
def download_json_file():
    # 生成JSON文件数据
    json_data = generate_json_string()
    if os.path.exists("/app/temp_json.json"):
        os.remove("/app/temp_json.json")
    # 保存JSON数据到临时文件
    with open("/app/temp_json.json", 'w') as f:
        # json.dump(json_data, f)
        f.write(json_data)
    # 发送JSON文件到前端
    return send_file("temp_json.json", as_attachment=True)


@app.route('/upload_json_file', methods=['POST'])
def upload_json_file():
    try:
        # 获取POST请求中的JSON文件内容
        file_content = request.get_data()
        # 将字节对象解码为字符串
        file_content_str = file_content.decode('utf-8')
        # 将JSON字符串保存到临时文件
        with open('/tmp_data.json', 'w') as f:
            json.dump(json.loads(file_content_str), f)
        with open("/tmp_data.json", 'r') as f:
            json_dict = json.load(f)
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM items")
        items = cursor.fetchall()
        # 将字典中的数据更新到数据库表
        for jsondata in json_dict['data']:
            link = jsondata.get('link')
            flag = False
            for item in items:
                if item[1] == link:
                    flag = True
                    break
            if flag:
                continue
            tag = jsondata.get('tag')
            cursor.execute("INSERT INTO items (name, value) VALUES (?, ?)", (link, tag))
            # 返回成功信息
            conn.commit()
        # 关闭数据库连接
        cursor.close()
        conn.close()
        os.remove("/tmp_data.json")
        return jsonify({'success': True})
    except Exception as e:
        print("An error occurred: ", e)
        return jsonify({'success': False})


@app.route('/process-file', methods=['POST'])
def process_file():
    if os.path.exists("/app/tmp.m3u"):
        os.remove("/app/tmp.m3u")
    # Get the uploaded file
    file = request.files['file']
    # Process the file to standardize it to m3u format
    new_content = format(file.readlines())
    with open("/app/tmp.m3u", "w") as f:
        f.write(new_content)
    # Return the processed file for download
    return send_file("tmp.m3u", as_attachment=True)


def formatStr(data):
    new_content = ""
    defalutname = "佚名"
    tmpurl = []
    for i in range(len(data)):
        line = data[i].strip()
        if line == "":
            continue
        # 假定直播名字和直播源不在同一行
        if line.startswith("#EXTINF"):
            continue
        # 不是http开头，可能是直播源
        if not line.startswith("http"):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,http", line):
                name, url = line.split(",", 1)
                if url in tmpurl:
                    continue
                tmpurl.append(url)
                if name:
                    new_content += f'#EXTINF:-1 tvg-name="{name}"\n{url}\n'
                else:
                    new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{url}\n'
            # 匹配:不是直播源和频道
            else:
                new_content += line + "\n"
        # http开始
        else:
            # 去重复
            if line in tmpurl:
                continue
            # index=0
            if i == 0:
                new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{line}\n'
                tmpurl.append(line)
                continue
            preline = data[i - 1].strip()
            # 没有名字
            if preline == "":
                new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{line}\n'
                tmpurl.append(line)
                continue
            # 不是名字
            if not preline.startswith("#EXTINF"):
                new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{line}\n'
                tmpurl.append(line)
                continue
            # 有名字
            else:
                new_content += f'{preline}\n{line}\n'
                tmpurl.append(line)
                continue
    return new_content


def format(data):
    new_content = ""
    defalutname = "佚名"
    tmpurl = []
    for i in range(len(data)):
        line = data[i].decode("utf-8").strip()
        if line == "":
            continue
        # 假定直播名字和直播源不在同一行
        if line.startswith("#EXTINF"):
            continue
        # 不是http开头，可能是直播源
        if not line.startswith("http"):
            # 匹配格式：频道,url
            if re.match(r"^[^#].*,http", line):
                name, url = line.split(",", 1)
                if url in tmpurl:
                    continue
                tmpurl.append(url)
                if name:
                    new_content += f'#EXTINF:-1 tvg-name="{name}"\n{url}\n'
                else:
                    new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{url}\n'
            # 匹配:不是直播源和频道
            else:
                new_content += line + "\n"
        # http开始
        else:
            # 去重复
            if line in tmpurl:
                continue
            # index=0
            if i == 0:
                new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{line}\n'
                tmpurl.append(line)
                continue
            preline = data[i - 1].decode("utf-8").strip()
            # 没有名字
            if preline == "":
                new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{line}\n'
                tmpurl.append(line)
                continue
            # 不是名字
            if not preline.startswith("#EXTINF"):
                new_content += f'#EXTINF:-1 tvg-name="{defalutname}"\n{line}\n'
                tmpurl.append(line)
                continue
            # 有名字
            else:
                new_content += f'{preline}\n{line}\n'
                tmpurl.append(line)
                continue
    return new_content


# Initialize the database
init_db()

if __name__ == '__main__':
    timer_thread = threading.Thread(target=timer_func)
    timer_thread.start()
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    finally:
        timer_thread.join()

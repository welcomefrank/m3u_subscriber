# 获取直播源URL
import json

import requests
def decrypt(content):
    # 提取返回内容中的密钥和数据
    key = content[0:8]
    data = content[8:]

    # 对数据进行解密
    result = ''
    for i in range(len(data)):
        result += chr(ord(data[i]) ^ ord(key[i % 8]))

    # 将解密后的数据转换为JSON格式并返回
    return json.loads(result)
url = 'http://m.douyu.com/288016'

# 发起HTTP请求获取直播源内容
response = requests.get(url)

# 对返回内容进行解密
content = response.content.decode('utf-8')
data = decrypt(content)
rtmp_url = data['data'][0]['rtmp_url']
rtmp_live = data['data'][0]['rtmp_live']

# 将视频流地址和格式拼接成新的直播源地址
converted_url = 'rtmp://' + rtmp_url + '/' + rtmp_live

# 输出转换后的直播源地址
print(converted_url)
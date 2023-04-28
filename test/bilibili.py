import requests

# 设置请求头
headers = {
    'Host': 'api.live.bilibili.com',
    'Referer': 'https://live.bilibili.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36',
}

# 直播间ID
room_id = '1024814'

# 请求参数
params = {
    "room_id": room_id,
    "no_playurl": 0,
    "mask": 1,
    "qn": 0,
    "platform": "web",
    "protocol": "0,1",
    "format": "0,2",
    "codec": "0,1"
}

# 发送请求
response = requests.get('https://api.live.bilibili.com/xlive/web-room/v2/index/getRoomPlayInfo', params=params, headers=headers)

# 获取直播源地址
playurl_info = response.json()['data']['playurl_info']
stream = playurl_info['playurl']['stream'][0] if 'stream' in playurl_info['playurl'] else playurl_info['durl'][0]
url_info = stream['format'][0]['codec'][1]['url_info'][0]
live_url = url_info['host'] + stream['format'][0]['codec'][1]['base_url'].split('?')[0]

print(live_url)

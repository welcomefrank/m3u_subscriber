import requests

url = 'https://tv.cctv.com/live/cctv4/index.shtml'  # 填写需要获取的直播页面 URL

# 发送请求并解析 HTML 页面
response = requests.get(url)
html = response.text

# 解析 M3U8 播放列表
if 'm3u8' in html:
    start_pos = html.find('https://')
    end_pos = html.find('.m3u8') + len('.m3u8')
    hls_url = html[start_pos:end_pos]

    # 输出 M3U 直播源内容
    print(f'#EXTINF:-1,CCTV4\n{hls_url}')
else:
    print('No live stream found')

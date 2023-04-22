import requests
from bs4 import BeautifulSoup

url = 'http://www.lshitv.com/cctv/cctv1.html'  # 填写需要获取的直播页面 URL

# 发送请求并解析 HTML 页面
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

# 查找页面中的直播链接（RTMP）
rtmp_url = ''
for script in soup.find_all('script'):
    if 'LivePlayer.init' in str(script):
        start_pos = str(script).find('play_url: "') + len('play_url: "')
        end_pos = str(script).find('"', start_pos)
        rtmp_url = str(script)[start_pos:end_pos]
        rtmp_url = rtmp_url.replace('\\/', '/')
        rtmp_url = rtmp_url.replace('&amp;', '&')

# 输出 M3U 直播源内容
if rtmp_url:
    print(f'#EXTINF:-1,CCTV1\n{rtmp_url}')
else:
    print('No live stream found')

import requests
from bs4 import BeautifulSoup

match_id = '57036'  # 填写需要获取的比赛 ID

# 发送请求并解析 HTML 页面
url = f'https://70zhibo.com/#/live?matchID={match_id}'
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

# 查找页面中的直播链接（HLS）
hls_url = ''
for script in soup.find_all('script'):
    if 'source: "http://' in str(script):
        start_pos = str(script).find('source: "http://')
        end_pos = str(script).find('.m3u8"') + len('.m3u8"')
        hls_url = str(script)[start_pos:end_pos]
        hls_url = hls_url.replace('\\', '')

# 输出 M3U 直播源内容
if hls_url:
    print(f'#EXTINF:-1,Live\n{hls_url}')
else:
    print('No live stream found')

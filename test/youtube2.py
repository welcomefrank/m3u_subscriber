import json

import requests

# 填写需要下载的直播ID，可以是一个列表
live_ids = ['u23MOITk4LM', 'o5_dejehU-Q']

# 生成直播流链接
live_urls = []
for live_id in live_ids:
    response = requests.get(f'https://www.youtube.com/watch?v={live_id}')
    player_response = response.text.split('ytInitialPlayerResponse = ')[1].split(';</script>')[0]
    video_info = json.loads(player_response)['streamingData']['adaptiveFormats']
    available_formats = {}
    for stream in video_info:
        if 'mimeType' not in stream or 'url' not in stream or 'qualityLabel' not in stream:
            continue
        mime_type = stream['mimeType']
        url = stream['url']
        quality = stream['qualityLabel']
        if 'video/webm' in mime_type and quality not in available_formats:
            available_formats[quality] = url
    if not available_formats:
        continue
    # 选择最佳质量的视频流
    live_url = available_formats[max(available_formats)]
    live_urls.append(live_url)

# 输出 M3U 直播源内容
for i, url in enumerate(live_urls):
    print(f'#EXTINF:-1,Live {i + 1}\n{url}')

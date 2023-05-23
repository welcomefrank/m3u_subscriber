import re

import requests
url = 'https://manifest.googlevideo.com/api/manifest/hls_variant/expire/1684838552/ei/OERsZLyZNNGA2roP4ZyDiAw/ip/2406%3A4440%3A0%3A106%3A0%3A0%3A14%3Aa/id/1-iS7LArMPA.3/source/yt_live_broadcast/requiressl/yes/tx/24537258/txs/24537256%2C24537257%2C24537258%2C24537259/hfr/1/playlist_duration/30/manifest_duration/30/maudio/1/vprv/1/go/1/pacing/0/nvgoi/1/keepalive/yes/fexp/24007246%2C24362685%2C51000013%2C51000023/dover/11/itag/0/playlist_type/DVR/sparams/expire%2Cei%2Cip%2Cid%2Csource%2Crequiressl%2Ctx%2Ctxs%2Chfr%2Cplaylist_duration%2Cmanifest_duration%2Cmaudio%2Cvprv%2Cgo%2Citag%2Cplaylist_type/sig/AOq0QJ8wRgIhAM9fZiCavVM90qxrBcnFmCMh3b5S1O0q0FwvDCdHPLeAAiEArOPKJ6OgnzCFqCBxdetUsNxH-F8lurE6YQrmGqQogBg%3D/file/index.m3u8'
response = requests.get(url).text

target_resolution = "1920x1080"
# 使用正则表达式匹配所有的直播源数据，并查找与目标分辨率匹配的项
pattern = r'#EXT-X-STREAM-INF:BANDWIDTH=\d+,CODECS=".+",RESOLUTION={0},.*\n(.+)'.format(target_resolution)
match = re.search(pattern, response)

if match:
    # 如果找到匹配项，将其中的直播源链接打印出来
    target_stream_url = match.group(1)
    print("Target stream URL:", target_stream_url)
else:
    print("没有找到 1920x1080 的画质。")

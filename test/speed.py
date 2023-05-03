import time
import requests
#网络传输速度
url = "http://113.207.84.197:8090/__cl/cg:live/__c/liaoningHD/__op/default/__f/index.m3u8"
start_time = time.time()
response = requests.get(url)
end_time = time.time()
transmission_speed = len(response.content) / (end_time - start_time)
print(transmission_speed)
data = response.raw.read(1024)
# if fps >= 30 and avg_bitrate >= 2000000 and transmission_speed >= 500000:
#     print("视频流畅度很高")
# elif fps >= 25 and avg_bitrate >= 1000000 and transmission_speed >= 200000:
#     print("视频流畅度一般")
# else:
#     print("视频流畅度较低")
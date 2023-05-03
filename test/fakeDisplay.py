import struct
import requests
url = "http://113.207.84.197:8090/__cl/cg:live/__c/liaoningHD/__op/default/__f/index.m3u8"
response = requests.get(url, stream=True)
data = response.raw.read(1024)
res_bytes = data[-10:-6]
resolution = struct.unpack(">HH", res_bytes)
width = resolution[0]
height = resolution[1]
pixels = height * width
if pixels >= 1280*720 :
    print("这是一路高清直播源")
else:
    print("这不是一路高清直播源")
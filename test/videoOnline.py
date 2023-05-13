import requests

url = "https://www.caiji04.com/home/cjapi/cfc7/mc10/vod/xml"
params = {
    "ac": "list",
    "pg": 1,
}

response = requests.get(url, params=params)

if response.status_code == 200:
    # 成功获取响应
    data = response.json()
    # 处理响应数据，提取视频信息等
    print(data)
else:
    # 处理请求失败的情况
    print("请求失败，状态码为：", response.status_code)

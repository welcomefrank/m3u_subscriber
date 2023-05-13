import json

import requests
from bs4 import BeautifulSoup

url = 'https://www.caiji04.com/home/cjapi/cfc7/mc10/vod/xml'

response = requests.get(url)
#dict=json.loads(response.text)
soup = BeautifulSoup(response.text, 'html.parser')

# 获取所有a标签中的href属性值
links = [link['href'] for link in soup.find_all('a')]

# 输出链接列表
print(links)

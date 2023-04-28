import re


with open('/test_channels_macau.m3u', 'rb') as f:
    file_content = f.read()
dict = ''
# 使用正则表达式匹配所有的tvg_name标记里的字符串数据
regex_pattern = r'tvg-name="(.*?)"'
all_matches = re.findall(regex_pattern, file_content.decode(encoding='utf-8'))
dict1 = {}
for i in all_matches:
    if i in dict1.keys():
        continue
    dict1[i] = ''
    dict += f"'{i}':" + f"'港澳台'" + ','

print(dict)

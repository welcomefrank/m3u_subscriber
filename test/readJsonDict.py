import json

import chardet


def checkbytes(url):
    if isinstance(url, bytes):
        return decode_bytes(url).strip()
    else:
        return url


def decode_bytes(text):
    # define a list of possible encodings
    encodings = ['utf-8', 'gbk', 'iso-8859-1', 'ascii', 'cp936', 'big5', 'shift_jis', 'koi8-r']

    # try each encoding until one works
    for encoding in encodings:
        try:
            return text.decode(encoding).strip()
        except (TypeError, UnicodeDecodeError):
            continue

    # if none of the above worked, use chardet to detect the encoding
    result = chardet.detect(text)
    decoded_text = text.decode(result['encoding']).strip()
    return decoded_text


with open('/data.json', 'rb') as f:
    file_content = f.read()

sourcedict = json.loads(checkbytes(file_content))

dict1 = {}
dict = '{'
for singleData in sourcedict:
    name = singleData.get('name')
    if name not in dict1.keys():
        dict1[name] = ''
        dict += f"\"{name}\":" + f"\"{'成人频道'}\"" + ','
    listdata = singleData.get('data')
    for coredata in listdata:
        code = coredata.get('code')
        if code not in dict1.keys():
            dict1[code] = ''
            dict += f"\"{code}\":" + f"\"{'成人频道'}\"" + ','

dict = dict[:-1]
dict += '}'
# 保存JSON数据到临时文件
with open('/成人频道.json', 'w', encoding='unicode_escape') as f:
    f.write(dict)

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


with open('/新建文本文档.txt', 'rb') as f:
    file_content = f.read()
arr = checkbytes(file_content).splitlines()
dict1 = {}
dict = '{'
for i in arr:
    front = i.split(' ')[0]
    if front in dict1.keys():
        continue
    dict1[front] = ''
    dict += f"\"{front}\":" + f"\"成人频道\"" + ','
dict = dict[:-1]
dict += '}'
# 保存JSON数据到临时文件
with open('/成人频道.json', 'w', encoding='utf-8') as f:
    f.write(dict)

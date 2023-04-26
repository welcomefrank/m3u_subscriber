import os

import requests


# author:  https://github.com/benmoose39
def grab(url):
    response = requests.get(url, timeout=15).text
    if '.m3u8' not in response:
        # response = requests.get(url).text
        if '.m3u8' not in response:
            # os.system(f'wget {url} -O temp.txt')
            os.system(f'curl "{url}" > temp.txt')
            response = ''.join(open('temp.txt').readlines())
            if '.m3u8' not in response:
                return
    end = response.find('.m3u8') + 5
    tuner = 100
    while True:
        if 'https://' in response[end - tuner: end]:
            link = response[end - tuner: end]
            start = link.find('https://')
            end = link.find('.m3u8') + 5
            break
        else:
            tuner += 5
    print(f"{link[start: end]}")


if __name__ == '__main__':
    grab('https://www.youtube.com/watch?v=YnLVEQ4-X9w')

import requests

import base64
import binascii
import hashlib
import datetime

from crypto.PublicKey import RSA


class LnyuntvService:
    def __init__(self):
        self.channel_map = {
            # 辽宁资讯广播
            'lnzx': ['badb989f4fd699b6e696a358847cb746', 'bdrmtvzb-new', '/bdrm/dlzxgb.m3u8', 'UZRRlkyF0ck8nPja',
                     'http://qvzc.bdy.lnyun.com.cn/']
        }

    def jiemi(self, message):
        # 私钥 pkcs1格式
        _priKey = '''-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAllpOo0kGVEkvFSxF
o8gh4kS8/2r63JVHtmfmpcXMFTMMsBLCLD2UlKx5GlWYvoGKQQHYUaKNPOpq15kc
y0VLewIDAQABAkBNY5xYdaz5U1YVutz5iXjPY3w4qBMJ2Ri5bc+NgjsiqX2QwTYn
3A3oeRffbFPAAOQHImd1a+QL9OLmN0vzSwx5AiEA+A5dVaI5vhj91duWbllxe5A5
a8uBD8Va5pyIcPPA2BUCIQCbKvFBo068ShpqBSMWuLgV2rlc4mNCrwlpihaFaBpp
TwIgYeAxHa/j/skXp0F8qs/qAipXLdxfcVya0HGlOIRFbD0CIQCFljTaU6Rnikyv
VfjdiO5DMmk/RFA8isFJsW6uL+/9FQIgZ9iE9+tlg3U6mPAWvnGplrUlOHJBQQ7f
B1HGDhiNmw0=
-----END PRIVATE KEY-----'''
        privateKey = RSA.import_key(_priKey)
        decrypted = privateKey.decrypt(base64.b64decode(message)).decode('utf-8')
        return decrypted

    def get(self, channel_id):
        if channel_id not in self.channel_map:
            channel_id = 'lnws'

        domain_id, url_prefix, url_path, msg, referer = self.channel_map[channel_id]

        # 直播时间戳需要加30分钟 也就是 +1800秒
        time_stamp = int(datetime.datetime.now().timestamp()) + 1800

        epg_url = f'https://bdrm.bdy.lnyun.com.cn/cloud/apis/live/api/program/getNewProgram?domainId={domain_id}&times={datetime.datetime.now().strftime("%Y-%m-%d")}'
        resepg = requests.get(epg_url)
        is_live = 1
        bak_url = ""
        if resepg.status_code == 200:
            data = resepg.json()['data']
            if len(data) > 0:
                epg_data = data[0]
                for i in range(len(epg_data['startTimeStamp'])):
                    start, end, name, pull_domain = epg_data['startTimeStamp'][i], epg_data['endTimeStamp'][i], \
                    epg_data['name'][i], epg_data['pullDomain'][i]
                    if start <= time_stamp and end >= time_stamp and '停播' in name:
                        is_live = 0
                        break
                    if '停播' not in name:
                        bak_url = pull_domain

        res = requests.post('https://bdrm.bdy.lnyun.com.cn/cloud/apis/live/api/domain/getOauth',
                            headers={'content-type': 'application/x-www-form-urlencoded'}, data={'domainId': domain_id})
        auth_key = None
        if res.status_code == 200:
            msg_dec = self.jiemi(res.json()['msg'])
            referer = 'http://' + self.jiemi(res.json()['data']['refer'])
            md5_message = f'{url_path}-{time_stamp}-0-0-{msg_dec}'.encode('utf-8')
            auth_key = f'{time_stamp}-0-0-{hashlib.md5(md5_message).hexdigest()}'
        if auth_key:
            url = f'https://{url_prefix}.lnyun.com.cn{url_path}?auth_key={auth_key}'
        else:
            url = f'{bak_url}{url_path}'

        return {
            'is_live': is_live,
            'url': url,
            'referer': referer,
        }

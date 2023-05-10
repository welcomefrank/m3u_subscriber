# auth = HTTPBasicAuth()

# flask密码验证，客户端服务器都需要密码验证才可以链接webdav视频
# @auth.verify_password
# def verify_password(username, password):
#     # 验证用户名和密码
#     if username == 'pi' and password == 'wanjun310':
#         return True
#     return False


@app.route('/stream')
# @auth.login_required
def stream():
    # 将 WebDAV 视频文件发送给客户端
    return send_file(
        'http://192.168.5.1:5244/dav/%E5%85%AC%E5%85%B1%E7%BD%91%E7%9B%98/1/%E6%88%91%E7%9A%84%E9%98%BF%E9%87%8C%E4%BA%91%E7%9B%98%EF%BC%88open%EF%BC%89/%E7%94%B5%E8%A7%86%E5%89%A7/Y%20%E5%8E%9F%E6%9D%A5%E6%88%91%E5%BE%88%E7%88%B1%E4%BD%A0/18.mp4',
        mimetype='video/mp4')


# @app.route('/fake_live_stream')
# def fake_live_stream():
#     # 重定向客户端到视频请求的路由
#     return redirect(url_for('stream'))


# 服务器验证一次，客户端不需要验证

SERVER_URL = 'http://192.168.5.1:5244'
WEBDAV_URL = SERVER_URL + '/dav/%E5%85%AC%E5%85%B1%E7%BD%91%E7%9B%98/1/%E6%88%91%E7%9A%84%E9%98%BF%E9%87%8C%E4%BA%91%E7%9B%98%EF%BC%88open%EF%BC%89'


# 验证WebDAV用户名和密码
def verify_password(username, password):
    url = WEBDAV_URL
    response = requests.get(url, auth=(username, password))
    if response.status_code == 200:
        return True
    else:
        return False


@app.route('/stream')
def stream():
    # 身份验证
    auth = request.authorization
    if not auth or not verify_password(auth.username, auth.password):
        return ('Unauthorized access', 401, {'WWW-Authenticate': 'Basic realm="Authentication Required"'})

    # 将 WebDAV 视频文件发送给客户端
    return send_file(WEBDAV_URL + '/18.mp4', mimetype='video/mp4')







SERVER_URL = 'http://192.168.5.1:5244'
WEBDAV_URL = SERVER_URL + '/dav/%E5%85%AC%E5%85%B1%E7%BD%91%E7%9B%98/1/%E6%88%91%E7%9A%84%E9%98%BF%E9%87%8C%E4%BA%91%E7%9B%98%EF%BC%88open%EF%BC%89'


@app.route('/stream')
def stream():
    # 将 WebDAV 视频文件发送给客户端
    return send_file(WEBDAV_URL + '/18.mp4', mimetype='video/mp4')




服务器验证webdav密码，客户端不需要密码验证，客户端需要把视频完整下载才可以播放


# WebDAV服务器的基本URL和用户名/密码
WEBDAV_URL = 'http://192.168.5.1:5244'
WEBDAV_AUTH = ('pi', 'wanjun310')

# 假的视频链接与真实WebDAV资源路径之间的映射关系
VIDEO_MAPPING = {
    'video1.mp4': '/dav/公共网盘/1/我的阿里云盘（open）/电视剧/J%20嘉南传.4K/01.mp4',
    'video2.mp4': '/path/to/real/video2.mp4'
    # ...
}


@app.route('/videos/<path:path>')
def video_stream(path):
    if path not in VIDEO_MAPPING.keys():
        return "Video not found", 404

    real_path = VIDEO_MAPPING[path]

    # 使用requests库从WebDAV服务器上获取真实视频文件，并将其作为流传输到客户端
    res = requests.get(WEBDAV_URL + real_path, auth=WEBDAV_AUTH, stream=True)
    headers = {'Content-Type': res.headers.get('Content-Type')}
    return Response(res.iter_content(chunk_size=10240), headers=headers, mimetype='video/MP2T')


@app.before_request
def require_auth():
    auth = request.authorization

    # 如果请求的URL属于/videos/*，则需要进行WebDAV身份验证
    # if request.path.startswith('/videos/') and (auth is None or not check_auth(auth.username, auth.password)):
    #     return Response('Authentication required', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})



def check_auth(username, password):
    """检查给定的用户名和密码是否正确"""
    return username == 'pi' and password == 'wanjun310'





    if os.path.isdir(SLICES_DIR):
        shutil.rmtree(SLICES_DIR)
    os.makedirs(SLICES_DIR)
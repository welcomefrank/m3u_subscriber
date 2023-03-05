# m3usubscriber
m3u超融合
简单的做了一个网络直播源连接工具
https://raw.githubusercontent.com/liudaoguiguzi/m3u_subscriber/main/%E5%9B%BE%E7%89%871.png
目前实现的功能如下:
1-保存来自互联网的直播源订阅链接
2-可以把所有保存的链接的配置文件下载后整合到一起，生成一个局域网直播源订阅链接，你可以通过这个直播源链接获取你保存的全部直播源链接内容
3-自带直播源订阅链接导入导出功能，导出的temp_json.json就是保存的直播源订阅链接，可以分享给其他人导入合并你的订阅链接
4-后台写死了每隔半小时会自动执行生成M3U超融合直播源订阅功能，即会自动刷新所有直播源订阅链接内容

使用步骤:
docker网络不好的情况下可以按照下面流程安装，否则直接第三步:
1-直接下载项目里的m3usubscriber.tar，把它放到linux-arm64位主机里
2-在同样的路径下执行  sudo docker load < m3usubscriber.tar
3-docker run -d --name m3usubscriber --restart unless-stopped -p 4395:80 -d m3usubscriber:latest

使用步骤:
1-新增网络直播源订阅/上传文件导入合并M3U超融合备份
2-生成M3U超融合直播源订阅
3-按照如下格式填写M3U超融合直播源订阅链接:
https://局域网docker所在主机ip:当前页面端口/url/A.m3u
举例子：docker挂在软路由上，软路由WAN 的ip地址是 192.168.5.1
你挂载这个容器的映射端口是4395
则直播源订阅链接为：
http://192.168.5.1:4395/url/A.m3u

缺点:
1-暂时做不到对订阅内部内容去重复，毕竟直播源文本填写格式都不统一，非常混乱
2-没有做直播源有效性检测，因为1的相同原因

吐槽:
1-做这个纯粹闲的蛋疼
2-做完才发现这玩意做数据库或者是密码本也是可以的，麻了，我到底做了什么工具
3-很久以前就想找这种工具来集成直播源，之前是用tvheadend,不过那玩意用着老是崩溃，检测直播源的有效性也很差，整个软件都非常低效臃肿
4-我只编译了arm64位系统的镜像，想要其他镜像的自己做吧：
    1- 把源码复制到一个文件夹下
    2- sudo docker build -t m3usubscriber .     
    3- docker run -d --name m3usubscriber --restart unless-stopped -p 4395:80 -d m3usubscriber:latest


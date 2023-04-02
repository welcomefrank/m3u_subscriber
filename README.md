# m3usubscriber
## m3u超融合

## 一个偏离初心的工具箱，目前有直播源订阅、直播源检测、白名单黑名单订阅、节点订阅、订阅合并、订阅加密、dns分流器等功能，主要是为了方便自己的网上冲浪做的，并不是很好入手


![image](https://raw.githubusercontent.com/paperbluster/m3u_subscriber/main/%E5%9B%BE%E7%89%871.png)

### 安装步骤:

#### 一、host模式:推荐使用，可以减少一层路由，并且不会导致dns出问题

## arm64:

docker run -d --name m3usubscriber-22771 --restart unless-stopped -p --net=host  jkld310/m3usubscriber:latest  

docker run -d --name m3usubscriber --restart unless-stopped --net=host --memory=500m --cpus=0.000 --privileged jkld310/m3usubscriber:latest

docker run -d --name m3usubscriber-22771 --restart unless-stopped --net=host -d jkld310/m3usubscriber:arm64v8

docker run -d --name m3usubscriber --restart unless-stopped --net=host --memory=500m --cpus=0.000 --privileged jkld310/m3usubscriber:arm64v8

## x86/amd64:

docker run -d --name m3usubscriber-22771 --restart unless-stopped --net=host -d jkld310/m3usubscriber:x86_64   

docker run -d --name m3usubscriber --restart unless-stopped --net=host --memory=500m --cpus=0.000 --privileged jkld310/m3usubscriber:x86_64

#### 二、bridge模式:不推荐使用，目前这个模式会导致dns分流器异常

## 默认arm64架构:

docker run -d --name m3usubscriber --restart unless-stopped -p 22770:22770 -p 22771:22771  jkld310/m3usubscriber:latest  

或者:

docker run -d --name m3usubscriber --restart unless-stopped -p 22770:22770 -p 22771:22771  jkld310/m3usubscriber:arm64v8

## adm64/x86_64架构:

docker run -d --name m3usubscriber --restart unless-stopped -p 22770:22770 -p 22771:22771  jkld310/m3usubscriber:x86_64   

### 非常高兴能为您介绍本工具所实现的各项功能：

1-您可以轻松保存来自互联网的直播源订阅链接；

比如:https://raw.githubusercontent.com/liudaoguiguzi/ppap/main/1.m3u

##### 2-将保存的链接整合为一个局域网直播源订阅链接，通过该链接，您可以在局域网内访问您所保存的所有直播源链接内容；

3-每个功能模块都有导入导出配置功能，顺便加了一键导入导出，这个只对订阅性质的功能有效

4-工具在后台每隔24小时会自动执行生成M3U超融合直播源订阅功能，即会自动刷新所有直播源订阅链接内容。

5-m3u文件标准格式转换，您可以上传M3U直播源文件获得去重复且格式统一的M3U文件，目前只有m3u格式的直播源文件，没有txt格式

6-M3U超融合链接自带第五条功能

7-加入并发加速处理(默认100线程)，本人使用树莓派4B可以在20秒之内下载8M的处理结果

##### 8-正式给m3u超融合加入了直播源检测，因为是异步检测，直播源数据会不断刷新

,编译后开启检测后前端无法感知检测，但是可以通过访问alive.m3u文件了解检测正在进行，alive.m3u文件和A.m3u文件地址类同,检测速度已经尽可能提升

9-设置了上传/下载的直播源文件最大限制为100M

10-添加了直播源本地存储，支持上传m3u文件和粘贴板复制把m3u资源永久存入，把有效直播源和网络直播源直接存到数据库里

11-加了一个切换页面，加了一个批量密码生成

12-添加了白名单、黑名单、ipv4\ipv6订阅，主要是拿来喂养openclash，自用

#### 13-添加了类似acl4ssr的功能，测试效果比较弱鸡,自用

#### 14-增加了基于redis的dns分流器，配合白名单和黑名单进行分流，转发7874端口(外国+中国域名漏网之鱼，可以使用openclash)，转发5336端口(大部分命中的中国域名，可以使用

adguardhome)，dns监听端口-22770(在软路由dhcp/dns设置转发127.0.0.1#22770)，自用

备注：dns分流器可以自己设置服务器和端口，建议使用host模式减少一层路由。

实际使用中建议把它作为软路由adguardhome插件的上游dns，adguardhome作为dnsmasq的上游，

在分流器里外国dns设置openclash，国内dns随便你填野生的114.114.114.114:53或者自己整的

这样子顺便可以集中使用adguardhome插件的广告过滤

同时adguardhome应该根据自己的网络状况调整最大ttl值，否则有些网站不能及时返回结果，

我测试100兆电信需要设置20000才可以正常访问外部网站

#### 15-增加了加密订阅功能，可以套娃订阅别人的加密订阅，在备注输入密码就可以自动解密加密文件下载

### 接下来，您只需要按照以下步骤即可使用本工具：

1-新增网络直播源订阅或上传文件导入合并M3U超融合备份；

2-生成M3U超融合直播源订阅；生成成功会有弹窗，网络异常或者下载订阅失败都会导致下面的A.m3u文件为空

3-按照以下格式填写M3U超融合直播源订阅链接：

http://局域网docker所在主机ip:当前页面端口/url/A.m3u

例如，若您的docker挂载在软路由上，软路由LAN的ip地址为192.168.5.1，

您挂载该容器的映射端口为4395，则直播源订阅链接应为：

http://192.168.5.1:4395/url/A.m3u

### 本人也必须坦诚地告诉您，本工具也存在一些缺点，包括：

1-直播源有效性检测效果一般，但是应该可以在网络直播源方面把tvheadend踩在脚下了，有点狂妄哈哈哈

2-镜像有点大，因为这是本人第一次自己构建镜像，针对镜像的大小后期会尝试优化减少

3-主要是为了自己网上冲浪畅通无阻写的，其他人使用起来应该很痛苦吧哈哈哈哈哈哈哈哈哈

4-dns分流器我只测试了基于host模式的状况，没兴趣走桥接模式多套一层路由，你可以自己试试看

5-dns分流器的黑白名单目前是共用一个线程的，我设置了并发上限为500个线程，我玩树莓派4B是可以开到1000都没压力的，

家庭使用的话500线程数已经非常流畅了

6-节点订阅服务器只能自己本地安装subconverter或者用公共的，内置了一些本地的配置模板，

subconverter很强大，我无法对其进行参考改造合并，尝试自己写的转换非常有问题，暂时放弃。

但是我希望可以做出一个多线程的转换服务器，这是subconverter的一个缺点似乎

7-代码写的有点烂，前端有些BUG无伤大雅的我就不折腾了

##### 8-内置的redis服务器似乎会因为容器关闭或者软路由断电导致数据库数据全部丢失，建议经常做好备份

### 此外，本人也希望借此机会进行一些吐槽：

1-制作本工具纯属出于兴趣和爱好（当然！）

2-制作完成后，因为莫名其妙的想法开始不断出现，所以该工具的功能会越来越多，当然也就意味着会越来越挑战硬件性能，目前塞了一个redis服务器进去了。

下次可能会塞个ffmpeg进去，有个想法想实现一下（越写越上头）

3-事实上，在很久以前，本人也一直在寻找一款类似工具来集成直播源。（完成！）

4-仅供个人使用，请勿商用，代码已经全部开源，后果自负



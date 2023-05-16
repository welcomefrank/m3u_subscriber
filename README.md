# m3usubscriber
## m3u超融合

## 一个偏离初心的工具箱，目前有直播源订阅、直播源检测、直播源分组、白名单黑名单订阅、节点订阅、订阅合并、订阅加密、dns分流器、youtube直播源等功能，主要是为了方便自己的网上冲浪做的，并不是很好入手
## PS:实际上是因为解决不了容器太大的问题干脆把所有工具全部放到这个项目里^_^


![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%871.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%872.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%873.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%874.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%875.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%876.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%877.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%878.png?raw=true)
### 安装步骤:

#### 一、host模式:推荐使用，可以减少一层路由，利好dns分流器

## 普通:一般用下面的就可以

docker run -d --name m3usubscriber  --restart unless-stopped --net=host -e TZ=Asia/Shanghai jkld310/m3usubscriber:latest

docker run -d --name m3usubscriber --restart unless-stopped --net=host -e TZ=Asia/Shanghai jkld310/m3usubscriber:arm64v8

docker run -d --name m3usubscriber --restart unless-stopped --net=host -e TZ=Asia/Shanghai jkld310/m3usubscriber:x86_64

## 特权:开放全部线程和管理权限

docker run -d --name m3usubscriber --restart unless-stopped --net=host --memory=1000m --cpus=0.000 --privileged=true --cap-add=ALL -e TZ=Asia/Shanghai jkld310/m3usubscriber:latest

docker run -d --name m3usubscriber  --restart unless-stopped --net=host --memory=1000m --cpus=0.000 --privileged=true --cap-add=ALL -e TZ=Asia/Shanghai jkld310/m3usubscriber:arm64v8

docker run -d --name m3usubscriber --restart unless-stopped --net=host --memory=500m --cpus=0.000 --privileged=true --cap-add=ALL -e TZ=Asia/Shanghai jkld310/m3usubscriber:x86_64

#### 二、bridge模式:不建议使用，可能有BUG

docker run -d --name m3usubscriber  --restart unless-stopped -p 22771:22771 -p 22770:22770 -p 22772:22772 -e TZ=Asia/Shanghai jkld310/m3usubscriber:latest

docker run -d --name m3usubscriber  --restart unless-stopped -p 22771:22771 -p 22770:22770 -p 22772:22772 -e TZ=Asia/Shanghai jkld310/m3usubscriber:arm64v8

docker run -d --name m3usubscriber  --restart unless-stopped -p 22771:22771 -p 22770:22770 -p 22772:22772 -e TZ=Asia/Shanghai jkld310/m3usubscriber:x86_64

### 非常高兴能为您介绍本工具所实现的各项功能：

1-您可以轻松保存来自互联网的直播源订阅链接；

比如:https://raw.githubusercontent.com/liudaoguiguzi/ppap/main/1.m3u

##### 2-将保存的链接整合为一个局域网直播源订阅链接，通过该链接，您可以在局域网内访问您所保存的所有直播源链接内容；

3-每个功能模块都有导入导出配置功能，顺便加了一键导入导出，这个只对订阅性质的功能有效

4-工具在后台每隔24小时会自动执行生成M3U超融合直播源订阅功能，即会自动刷新所有直播源订阅链接内容。

5-m3u文件标准格式转换，您可以上传M3U直播源文件获得去重复且格式统一的M3U文件

6-M3U超融合链接自带第五条功能

7-加入并发加速处理(默认100线程)

##### 8-正式给m3u超融合加入了直播源检测，因为是异步检测，直播源数据会不断刷新

,编译后开启检测后前端无法感知检测，但是可以通过刷新访问alive.m3u文件了解检测正在进行

9-设置了上传/下载的直播源文件最大限制为100M

10-添加了直播源本地存储，支持上传m3u文件和粘贴板复制把m3u资源永久存入，把有效直播源和网络直播源直接存到数据库里

11-一些离线工具

12-添加了白名单、黑名单、ipv4\ipv6订阅，主要是拿来喂养openclash，自用喂养DNS分流器功能

#### 13-添加了类似acl4ssr的功能，需要额外安装docker容器subconverter或者公共转换服务器，我直接把acl4ssr作者的代理模板存进去了，做了保底措施，当只能下载其他情况全部失效的情况下会把一个加密订阅解锁后作为最终代理文件

#### 14-增加了基于redis的dns分流器，配合白名单和黑名单进行分流，转发7874端口(外国+中国域名漏网之鱼，可以使用openclash)，转发5336端口(大部分命中的中国域名，可以使用

adguardhome)，dns监听端口-22770(在软路由dhcp/dns设置转发127.0.0.1#22770)，自用

备注：dns分流器可以自己设置服务器和端口，建议使用host模式减少一层路由。

实际使用中建议把它作为软路由adguardhome插件的上游dns，adguardhome劫持dnsmasq的53端口，

在分流器里外国dns设置openclash，国内dns我填写了第二个adguardhome，这个全部是大陆dns

这样子顺便可以集中使用adguardhome插件的广告过滤

#### 15-增加了加密订阅功能，可以套娃订阅别人的加密订阅，在备注输入密码就可以自动解密加密文件下载

#### 16-增加了简易DNS分流黑白名单，可以选择手动维护，也可以选择开启系统自动维护，该部分主要是记录个人日常冲浪习惯的域名，黑白名单订阅是这个数据的来源和兜底

17-加了开关细化控制各个功能

#### 18-同步账户支持GITEE,GITHUB,WEBDAV。用途只有一个，把文件加密后同步到公共平台

19-增加了搜索功能

#### 20-订阅文件重命名，同步上传的订阅文件现在支持自命名，不支持格式修改，默认txt

21-直播源垃圾过滤，禁止关键字相关直播源数据入库

#### 22-直播源白名单分组优先级，根据优先级来配置优先筛选直播源对其归类为对应分组，数字越小分组越优先

#### 23-通用网络文件下载加密后上传至同步账号，支持自定义文件名字，包括格式

#### 24-通用下载加密订阅解密，配合23可以实现客户机对服务器两者数据传递

#### 25-参考benmoose39大佬的项目https://github.com/benmoose39/YouTube_to_m3u，加入了youtube转直播源订阅功能，该功能生成的直播源列表会自动追加在白名单和有效直播源里，定时器功能需要在功能开关开启

#### 26-添加了webdav直播，可以把webdav子目录下的全部视频转换成直播源链接，不可以填写根目录，最好是目标视频最近的子目录，这里是根据alist在局域网情况下webdav传输开发的

#### 27-添加了alist直播，可以使用别人的alist网站，格式：https://domain.com/ ，之后程序会自动从根目录穷举查出全部视频文件，尽可能避免套娃的alist网站，仍然有一些网站无法爬取，有些是因为触发了对方网站的请求上限暂时无法爬虫,有的是因为对方alist网站做了特殊手段无法爬取，可以把这些网站汇总让我研究一下

### 接下来，您只需要按照以下步骤即可使用本工具：

1-新增网络直播源订阅或上传文件导入合并M3U超融合备份；

2-生成M3U超融合直播源订阅；生成成功会有弹窗，网络异常或者下载订阅失败都会导致下面的A.m3u文件为空

3-按照以下格式填写M3U超融合直播源订阅链接：

http://局域网docker所在主机ip:当前页面端口/url/A.m3u

例如，若您的docker挂载在软路由上，软路由LAN的ip地址为192.168.5.1，

您挂载该容器的映射端口为22771，则直播源订阅链接应为：

http://192.168.5.1:22771/url/A.m3u

### 本人也必须坦诚地告诉您，本工具也存在一些缺点，包括：

#### 1-直播源有效性检测比较简单，仅仅通过连通性测试来完成，并且由于大超量并发检测导致可能存在被网站当成爬虫攻击被拉黑IP，自己权衡是否使用该功能

2-镜像有点大，已经压缩到200兆了，有在考虑要不要放弃nginx，塞了一个redis哈哈哈哈哈！

redis导致镜像在不断变大有点蛋疼,当然你只使用dns分流器的话这个趋势会很慢

3-主要是为了自己网上冲浪畅通无阻写的，其他人使用起来应该很痛苦吧哈哈哈哈哈哈哈哈哈

4-dns分流器我只测试了基于host模式的状况，没兴趣走桥接模式多套一层路由，你可以自己试试看

5-dns分流器并发查询设置为90，每个查询拥有最大100线程，一般情况只允许10个线程，想试试100线程，可以设置线程为0，重启容器后就是100了

6-节点订阅服务器只能自己本地安装subconverter或者用公共的，内置了一些本地的配置模板，

subconverter很强大，我无法对其进行参考改造合并，尝试自己写的转换非常有问题，暂时放弃。

但是我希望可以做出一个多线程的转换服务器，这是subconverter的一个缺点似乎

7-代码写的有点烂，前端有些BUG无伤大雅的我就不折腾了

8-epg没做，因为是整合网络全部直播源，所以资源格式乱七八糟，目前以整合优化格式为主

9-dns分流器第一次遇到的域名请求全都是对黑白名单全部数据进行查询，所以第一次比较慢，第一次命中后会把命中域名规则和查询的域名全部缓存起来，后期查询速度就非常快

10-dns分流器虽然实现了完全自动化，目前没有接入ip分流，主要是ip分流写出BUG了@_@

11-dns分流器目前基于域名分流，如果订阅的黑白域名组有脏东西的话还是会导致分流异常；同时域名分流仅仅基于子域名匹配规则来进行，可以应付大多数情况

12-alist/webdav直播只支持同时存在一个客户端使用，视频无法携带字幕，建议选择mp4硬编码字幕的资源，音频是flac的情况直播可能会没有声音去系统配置改成aac编码就行了。宽带和视频文件大小影响太严重的情况下要特别关注docker内存是否够用，因为切片数据都是存在容器里的，定时删除切片数据适当调长一点防止直播时数据被删掉了，如果网速非常好，视频不算很大的情况，这些参数设置成几分钟就好了

### 最后：

1-制作本工具纯属出于兴趣和爱好（当然！）

2-制作完成后，因为莫名其妙的想法开始不断出现，所以该工具的功能会越来越多，当然也就意味着会越来越挑战硬件性能，目前塞了一个redis服务器进去了。

下次可能会塞个ffmpeg进去，有个想法想实现一下（越写越上头）

3-事实上，在很久以前，本人也一直在寻找一款类似工具来集成直播源。（完成！）

4-仅供个人使用，请勿商用，代码已经全部开源，后果自负

5-该镜像主要是辅助openclash使用的，可以稍微解决国内分流的糟糕体验

6-有兴趣提供交流想法的朋友可以来电报群沟通https://t.me/+4swJ9h40iLQ3ZTVl

7-各位朋友有兴趣打赏一下叫花子吧,您的赞助可以更大地激励我维护该项目:

比特币

![image](https://github.com/paperbluster/m3u_subscriber/blob/main/bitcoin.png?raw=true)

bitcoin:BC1QCA337CSCNUFCGLLKZF4UTPLFX0YDZ66UAE38U9?amount=0.00010000&label=%E8%AF%B7%E6%88%91%E5%96%9D%E6%9D%AF%E8%8C%B6%E5%90%A7&message=%E8%AF%B7%E6%88%91%E5%96%9D%E6%9D%AF%E8%8C%B6%E5%90%A7

bc1qca337cscnufcgllkzf4utplfx0ydz66uae38u9



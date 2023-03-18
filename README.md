# m3usubscriber
## m3u超融合

简单的做了一个网络直播源连接工具


![image](https://raw.githubusercontent.com/liudaoguiguzi/m3u_subscriber/main/%E5%9B%BE%E7%89%871.png)

### 安装步骤:

#### 一、bridge模式:

默认arm64架构:

docker run -d --name m3usubscriber --restart unless-stopped -p 4395:4395  jkld310/m3usubscriber:latest  

或者:

docker run -d --name m3usubscriber --restart unless-stopped -p 4395:4395  jkld310/m3usubscriber:arm64v8

adm64/x86_64架构:

docker run -d --name m3usubscriber --restart unless-stopped -p 4395:4395  jkld310/m3usubscriber:x86_64   

#### 二、host模式:

arm64:

docker run -d --name m3usubscriber-4395 --restart unless-stopped -p --net=host  jkld310/m3usubscriber:latest  

docker run -d --name m3usubscriber-4395 --restart unless-stopped --net=host -d jkld310/m3usubscriber:arm64v8

x86/amd64:

docker run -d --name m3usubscriber-4395 --restart unless-stopped --net=host -d jkld310/m3usubscriber:x86_64   

### 非常高兴能为您介绍本工具所实现的各项功能：

1-您可以轻松保存来自互联网的直播源订阅链接；

比如:https://raw.githubusercontent.com/liudaoguiguzi/ppap/main/1.m3u

2-将保存的链接整合为一个局域网直播源订阅链接，通过该链接，您可以在局域网内访问您所保存的所有直播源链接内容；

3-工具内置直播源订阅链接的导入和导出功能，您可以将导出的temp_json.json分享给其他人，从而与他人共享订阅链接；

4-工具在后台每隔1小时会自动执行生成M3U超融合直播源订阅功能，即会自动刷新所有直播源订阅链接内容。

5-m3u文件标准格式转换，您可以上传M3U直播源文件获得去重复且格式统一的M3U文件

6-M3U超融合链接自带第五条功能

7-加入并发加速处理(默认100线程)，本人使用树莓派4B可以在20秒之内下载8M的处理结果

##### 8-正式给m3u超融合加入了直播源检测，因为是异步检测，直播源数据会不断刷新

,编译后开启检测后前端无法感知检测，但是可以通过访问B.m3u文件了解检测正在进行，B.m3u文件和A.m3u文件地址类同

9-设置了上传/下载的直播源文件最大限制为100M

10-添加了直播源本地存储，支持上传m3u文件和粘贴板复制把m3u资源永久存入

11-加了一个切换页面，加了一个批量密码生成

12-添加了白名单、黑名单、ipv4\ipv6订阅

### 接下来，您只需要按照以下步骤即可使用本工具：

1-新增网络直播源订阅或上传文件导入合并M3U超融合备份；

2-生成M3U超融合直播源订阅；生成成功会有弹窗，网络异常或者下载订阅失败都会导致下面的A.m3u文件为空

3-按照以下格式填写M3U超融合直播源订阅链接：

http://局域网docker所在主机ip:当前页面端口/url/A.m3u

例如，若您的docker挂载在软路由上，软路由WAN的ip地址为192.168.5.1，

您挂载该容器的映射端口为4395，则直播源订阅链接应为：

http://192.168.5.1:4395/url/A.m3u

### 本人也必须坦诚地告诉您，本工具也存在一些缺点，包括：

1-暂时没有做直播源有效性检测，有些代码要优化，这个功能在将来一定会上线

2-镜像有点大，因为这是本人第一次自己构建镜像，针对镜像的大小后期会尝试优化减少

### 此外，本人也希望借此机会进行一些吐槽：

1-制作本工具纯属出于兴趣和爱好

2-制作完成后，本人也发现该工具也可以作为数据库或密码本使用，本人也感到非常无奈；

3-事实上，在很久以前，本人也一直在寻找一款类似工具来集成直播源。

以前本人使用过tvheadend，不过tvheadend总是崩溃，检测直播源的有效性也有比较大落差，并且其主要目的并不是完全为这种目的服务

4-目前本人只编译了arm64位系统的镜像，需要其他镜像的您按照一下步骤编译：

     把源码复制到一个文件夹下
    
     sudo docker build -t m3usubscriber .     
    
     docker run -d --name m3usubscriber --restart unless-stopped -p 4395:4395 -d m3usubscriber:latest
     
5-直播源检测的逻辑感觉比较迷茫，有谁有什么思路可以分享一下


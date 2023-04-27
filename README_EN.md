# m3usubscriber

## A toolbox that deviates from the original intention. It currently has functions such as live source subscription, live source detection, live source grouping, whitelist and blacklist subscription, node subscription, subscription merger, subscription encryption, dns splitter, youtube live source, etc., mainly For the convenience of my own surfing, it is not very easy to start

![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%871.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%872.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%873.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%874.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%875.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%876.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%877.png?raw=true)
![image](https://github.com/paperbluster/m3u_subscriber/blob/main/%E5%9B%BE%E7%89%878.png?raw=true)

### INSTALL STEPS:

#### 一、host mode:best choice

## normal:

docker run -d --name m3usubscriber  --restart unless-stopped --net=host -d jkld310/m3usubscriber:latest

docker run -d --name m3usubscriber --restart unless-stopped --net=host -d jkld310/m3usubscriber:arm64v8

docker run -d --name m3usubscriber --restart unless-stopped --net=host -d jkld310/m3usubscriber:x86_64

## privilege:

docker run -d --name m3usubscriber --restart unless-stopped --net=host --memory=500m --cpus=0.000 --privileged=true --cap-add=ALL -d jkld310/m3usubscriber:latest

docker run -d --name m3usubscriber  --restart unless-stopped --net=host --memory=500m --cpus=0.000 --privileged=true --cap-add=ALL -d jkld310/m3usubscriber:arm64v8

docker run -d --name m3usubscriber --restart unless-stopped --net=host --memory=500m --cpus=0.000 --privileged=true --cap-add=ALL -d jkld310/m3usubscriber:x86_64

#### 二、bridge:There may be bugs

docker run -d --name m3usubscriber  --restart unless-stopped -p 22771:22771 -p 22770:22770 -p 22772:22772 -d jkld310/m3usubscriber:latest

docker run -d --name m3usubscriber  --restart unless-stopped -p 22771:22771 -p 22770:22770 -p 22772:22772 -d jkld310/m3usubscriber:arm64v8

docker run -d --name m3usubscriber  --restart unless-stopped -p 22771:22771 -p 22770:22770 -p 22772:22772 -d jkld310/m3usubscriber:x86_64

### I am very happy to introduce you to the various functions implemented by this tool:

1- You can easily save the subscription link of the live broadcast source from the Internet;

For example: https://raw.githubusercontent.com/liudaoguiguzi/ppap/main/1.m3u

##### 2-Integrate the saved link into a LAN live source subscription link, through which you can access all the saved live source link content in the LAN;

3- Each functional module has an import and export configuration function. By the way, one-click import and export is added. This is only valid for subscription-type functions

4- The tool will automatically execute the function of generating M3U hyper-converged live source subscription every 24 hours in the background, that is, it will automatically refresh the content of all live source subscription links.

5-m3u file standard format conversion, you can upload M3U live broadcast source files to get M3U files with deduplication and uniform format

6-M3U hyper-converged link comes with the fifth function

7- Add concurrent accelerated processing (default 100 threads)

##### 8- Officially added live source detection to m3u super fusion, because it is asynchronous detection, live source data will be refreshed continuously

, After compiling and enabling the detection, the front end cannot perceive the detection, but you can refresh and access the alive.m3u file to know that the detection is in progress

9- Set the maximum limit of uploaded/downloaded live source files to 100M

10- Added local storage of live broadcast sources, supports uploading m3u files and copying pasteboard to permanently store m3u resources, and directly saves valid live broadcast sources and network live broadcast sources into the database

11- Some offline tools

12-Added whitelist, blacklist, ipv4\ipv6 subscription, mainly used to feed openclash, self-feeding DNS splitter function

#### 13- Added acl4ssr-like functions, you need to install additional docker container subconverter or public conversion server, I directly saved the proxy template of the author of acl4ssr, and made a bottom-line guarantee, when you can only download other cases, all invalid Under the circumstances, an encrypted subscription will be unlocked as the final proxy file

#### 14- Added redis-based dns splitter, with whitelist and blacklist for splitting, forwarding port 7874 (for foreign + Chinese domain names, you can use openclash), forwarding port 5336 (most of the hits in China domain name, you can use

adguardhome), dns listening port -22770 (set forwarding 127.0.0.1#22770 in the soft router dhcp/dns), for personal use

Remarks: The dns splitter can set the server and port by itself. It is recommended to use the host mode to reduce one layer of routing.

In actual use, it is recommended to use it as the upstream dns of the soft routing adguardhome plug-in, adguardhome hijacks the 53 port of dnsmasq,

In the diverter, set openclash for foreign dns, and I filled in the second adguardhome for domestic dns, which are all mainland dns

In this way, by the way, you can use the ad filtering of the adguardhome plug-in centrally

#### 15-Encrypted subscription function has been added, you can set up a doll to subscribe to other people's encrypted subscriptions, and enter the password in the remarks to automatically decrypt encrypted files for download

#### 16- Added a simple DNS split black and white list, you can choose to maintain manually, or you can choose to open the automatic maintenance of the system, this part is mainly to record the domain names of personal daily surfing habits, black and white list subscription is the source and bottom line of this data

17- Added a switch to refine the control of each function

#### 18-Synchronization accounts support GITEE, GITHUB, WEBDAV. There is only one purpose, to encrypt files and synchronize them to the public platform

19 - Added search function

#### 20- Subscription file renaming, synchronously uploaded subscription files now support self-naming, do not support format modification, default txt

21-Live source spam filtering, prohibit keyword-related live source data from entering the database

#### 22-Live source whitelist group priority, according to the priority to configure priority screening live source to classify it into the corresponding group, the smaller the number, the higher the priority

#### 23- General network files are downloaded and encrypted and then uploaded to the synchronization account. Custom file names are supported, including the format

#### 24-Universal download encryption subscription decryption, cooperate with 23 to realize the data transmission between the client and the server

#### 25-Refer to the project of benmoose39 https://github.com/benmoose39/YouTube_to_m3u, adding the youtube to live source subscription function, the live source list generated by this function will be automatically added to the white list and valid live source , the timer function needs to be turned on at the function switch


### Next, you just need to follow the steps below to use this tool:

1- Added webcast source subscription or uploaded files to import and merge M3U hyper-converged backup;

2- Generate M3U hyper-converged live broadcast source subscription; there will be a pop-up window if the generation is successful, network abnormality or download subscription failure will cause the following A.m3u file to be empty

3- Fill in the M3U hyper-converged live source subscription link in the following format:

http://local area network docker host ip:current page port/url/A.m3u

For example, if your docker is mounted on the soft router, the IP address of the soft router LAN is 192.168.5.1,

The mapped port where you mount the container is 22771, then the live feed subscription link should be:

http://192.168.5.1:22771/url/A.m3u

### I must also be honest with you that this tool has some shortcomings, including:

#### 1-Live source validity detection is relatively simple, it is only done through connectivity test, and due to the large amount of concurrent detection, there may be cases where the website may be regarded as a crawler attack and be blacked out IP, weigh whether to use this function by yourself

2- The mirror image is a bit big, and it has been compressed to 200 megabytes. I am considering whether to give up nginx and plug in a redis hahahahaha!

Redis makes the image bigger and bigger, which is a bit painful. Of course, if you only use dns splitter, this trend will be very slow.

3- It is mainly written for the unimpeded surfing of the Internet. It should be painful for others to use it hahahahahahahahahaha

4-dns splitter I only tested the situation based on the host mode, I am not interested in using the bridge mode to set up an additional layer of routing, you can try it yourself

5-Dns shunt concurrent query is set to 90, each query has a maximum of 100 threads, generally only 10 threads are allowed, if you want to try 100 threads, you can set the thread to 0, and it will be 100 after restarting the container

6-Node subscribers can only install subconverter locally or use public ones. Some local configuration templates are built in.

The subconverter is very powerful, and I can't use it for reference transformation and merging. It is very problematic to try to write the conversion by myself, so I give up for the time being.

But I wish I could make a multi-threaded conversion server, this is a shortcoming of subconverter seems

7- The code is a bit rotten, and some bugs in the front end are harmless, so I won’t bother

8-epg is not done, because it integrates all live broadcast sources on the network, so the resource format is messy, and currently the integrated and optimized format is the main format

9-The first domain name request encountered by the dns splitter is to query all the data in the black and white lists, so the first time is relatively slow. After the first hit, it will cache all the domain names that hit the domain name rule and query, and query later very fast

Although the 10-dns splitter has been fully automated, it is not connected to the ip splitter at present, mainly because the ip splitter has written a BUG @_@

11-dns splitter is currently based on domain name splitting, if there are dirty things in the subscribed black and white domain name group, it will still lead to splitting exceptions; at the same time, domain name splitting is only based on subdomain name matching rules, which can handle most situations

### at last:

1- This tool was made purely as a hobby and hobby (of course!)

2- After the production is completed, because inexplicable ideas continue to appear, the functions of the tool will become more and more, which of course means that the hardware performance will be more and more challenging. Currently, a redis server is plugged into it.

I might put ffmpeg in next time, I have an idea I want to realize (the more I write, the more I write)

3-In fact, a long time ago, I have been looking for a similar tool to integrate live broadcast sources. (Finish!)

4- For personal use only, please do not use commercially, the code has been fully open source, and you will be responsible for the consequences

5- This image is mainly used to assist openclash, which can slightly solve the bad experience of domestic shunting

6- Friends who are interested in providing communication ideas can come to the telegram group to communicate https://t.me/+4swJ9h40iLQ3ZTVl

7- Friends who are interested in rewarding Beggars, your sponsorship can motivate me to maintain this project:

bitcoin

![image](https://github.com/paperbluster/m3u_subscriber/blob/main/bitcoin.png?raw=true)

bitcoin:BC1QCA337CSCNUFCGLLKZF4UTPLFX0YDZ66UAE38U9?amount=0.00010000&label=%E8%AF%B7%E6%88%91%E5%96%9D%E6%9D%AF%E8%8C%B6%E5%90%A7&message=%E8%AF %B7%E6%88%91%E5%96%9D%E6%9D%AF%E8%8C%B6%E5%90%A7

bc1qca337cscnufcgllkzf4utplfx0ydz66uae38u9

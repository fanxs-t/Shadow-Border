# Shadow-Border
被动漏洞扫描系统 Passive Vulnerability Scanning

Shadow Border是个被动扫描框架，用于渗透测试中的被动扫描、信息收集等并发的任务，目前只有少量POC，使用了Burpsuite，Redis和python，使用者可自定义poc进行被动扫描。

总体上参考[GourdScanV2](https://github.com/ysrc/GourdScanV2)，通过设置代理转发请求，针对请求进行漏洞扫描，最后在WEB界面显示扫描结果。基于作者自己的渗透测试方法和习惯，Shadow Border选择了使用Burpsuite来做请求的镜像来提高代理速度，之后通过Redis做请求存储，python起的scanner针对请求做扫描。Python的scanner参考[Poc-T](https://github.com/Xyntax/POC-T)。


## 简介：
主要的框架为：
![](http://148.70.228.11/upload/0f751b72ab73ca6bcf5a76881f0e085b.png)
1. 测试时设置Burpsuite代理，通过Burpsuite插件，提取请求包的信息，发送到Redis。
2. Python开启Web Server，在Web页面中点击启动Scanner。
3. Scanner初始化后，从Redis中获取请求数据。
4. Scanner Engine调用poc，对请求进行扫描。
5. 扫描结果存入Redis，在Web页面展示。

使用：
1. 运行ShadowBorder脚本，登录后，对scanner进行设置。设置允许扫描和镜像的请求http method，请求域名白名单，黑名单，redis账号，管理页面账号等数据。
![](http://148.70.228.11/upload/0609016cd9b2f252dbadbb5bcb6d88dc.png)
2. 测试时设置Burp代理，加载Shadow Border插件，将请求镜像发送到Redis:
![](http://148.70.228.11/upload/1d55900a28e9e3e4569954a3dc6c2f88.png)
3. 选择使用的poc后，开启scanner
![](http://148.70.228.11/upload/d9d9cb65d84258f2470b69f5963a3247.png)
4. 查看扫描状态：
![](http://148.70.228.11/upload/77f0e59fd36b22df4fd181ae4d523d46.png)

## 依赖：
- Python 3.4以上
- Burpsuite
- Redis
- treelib (python库)
- requests (python库)
- tornado (python库)
- redis (python库)
- gevent (python库)


## 详情：
https://sec.mrfan.xyz/2020/02/02/被动扫描系统%20-%20Shadow%20Border/
# 欢迎浏览本项目！
## 它是什么？
这是一个简单的通讯工具，使用python编写，通过socket进行通信，同时还支持用户信息校验和聊天记录存储及管理的功能。
## 我应该如何使用？
### 服务端
我们提供docker部署，无需繁琐的配置，在[这里](https://github.com/xhdndmm/meow-chat/releases)下载源码，解压进入server文件夹，然后
```
touch server.log users.db chat.json && sudo docker-compose up -d
```
即可
- 注意：需要开放12345端口
### 客户端
由于编译完体积较大，所以暂不提供编译好的版本，需要准备好python环境，安装依赖
```
pip install -r requirements.txt
```
# 欢迎浏览本项目！
## 它是什么？
这是一个简单的通讯工具，使用Python编写，通过Socket进行通信，使用base64编码，同时使用SQLite管理用户信息和聊天记录。
## 我应该如何使用？
### 服务端
我们提供docker部署，无需繁琐的配置，在[这里](https://github.com/xhdndmm/meow-chat/releases)下载源码，解压进入server文件夹，然后
```
touch server.log server_data.db  && sudo docker-compose up -d
```
即可
- 注意：需要开放12345端口
- `server.log`是日志，`server_data.db`是服务器数据库
### 客户端
由于编译完体积较大，所以暂不提供编译好的版本，需要准备好[Python](https://www.python.org/downloads/release/python-3128/)环境，并安装依赖
```
pip install -r requirements.txt
```
- 客户端会生成`local_chat.db`文件，这个是存储聊天记录的数据库
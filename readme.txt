用下面这两个命令产生cacert.pem和privkey.pem文件：
openssl genrsa -out privkey.pem 2048
openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095

编译：
cc sslserver.c -o sslserver -lssl -lcrypto
cc sslclient.c -o sslclient -lssl -lcrypto

运行程序用如下命令：
./sslserver 7878 cacert.pem privkey.pem
./sslclient 127.0.0.1 7878



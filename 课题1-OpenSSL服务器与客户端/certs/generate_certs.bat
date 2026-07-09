@echo off
set OPENSSL_CONF=openssl.cnf

echo ================================
echo 生成CA根证书
echo ================================
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=MyCA/O=Information Security/C=CN"

echo.
echo ================================
echo 生成服务器证书请求
echo ================================
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost/O=Server/C=CN"

echo.
echo ================================
echo 签发服务器证书
echo ================================
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

echo.
echo ================================
echo 生成客户端证书请求
echo ================================
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=client/O=Client/C=CN"

echo.
echo ================================
echo 签发客户端证书
echo ================================
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

echo.
echo ================================
echo 生成证书吊销列表(CRL)
echo ================================
openssl ca -gencrl -out crl.pem -crldays 30

echo.
echo 证书生成完成！
echo CA根证书: ca.crt
echo CA私钥: ca.key
echo 服务器证书: server.crt
echo 服务器私钥: server.key
echo 客户端证书: client.crt
echo 客户端私钥: client.key
echo 证书吊销列表: crl.pem
# ECDSASharp
使用C#读写OpenSSL产生的椭圆私钥和公钥

#openssl 相关命令

    * 产生椭圆私钥 *
    # openssl ecparam -genkey -name prime256v1 -out k.pem

## 根据私钥产生公钥
    # openssl ec -in k.pem -pubout -out p.pem

## 文本方式查看私钥
    # openssl ec -in k.pem -noout –text

## 签名
    # openssl dgst -sha256 -out hello.sig -sign k.pem hello.txt

## 验证签名
    # openssl dgst -sha256 -signature hello.sig -verify p.pem hello.txt

## 查看二进制的验证文件
    # cat hello.sig | hexdump
    # cat hello.sig | base64

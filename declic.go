package main

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    // "os"
)

func main() {
    // 定义命令行参数
    publicKeyFile := flag.String("key", "", "公钥文件路径")
    encryptedFile := flag.String("in", "", "需要解密的文件")
    outputFile := flag.String("out", "", "解密后的输出文件")
    flag.Parse()

    // 检查参数
    if *publicKeyFile == "" || *encryptedFile == "" || *outputFile == "" {
        fmt.Println("使用方法: program -key public.pem -in encrypted.bin -out decrypted.txt")
        flag.PrintDefaults()
        return
    }

    // 读取公钥文件
    pubKeyData, err := ioutil.ReadFile(*publicKeyFile)
    if err != nil {
        log.Fatalf("无法读取公钥文件: %v", err)
    }

    // 解析PEM格式的公钥
    block, _ := pem.Decode(pubKeyData)
    if block == nil {
        log.Fatal("无法解码PEM块")
    }

    // 解析公钥
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        log.Fatalf("解析公钥失败: %v", err)
    }

    // 转换为RSA公钥
    rsaPub, ok := pub.(*rsa.PublicKey)
    if !ok {
        log.Fatal("不是有效的RSA公钥")
    }

    // 读取加密文件
    encryptedData, err := ioutil.ReadFile(*encryptedFile)
    if err != nil {
        log.Fatalf("读取加密文件失败: %v", err)
    }

    // 解密数据
    decrypted, err := rsa.DecryptPKCS1v15(nil, rsaPub, encryptedData)
    if err != nil {
        log.Fatalf("解密失败: %v", err)
    }

    // 将解密后的数据写入输出文件
    err = ioutil.WriteFile(*outputFile, decrypted, 0644)
    if err != nil {
        log.Fatalf("写入输出文件失败: %v", err)
    }

    fmt.Println("解密完成，结果已保存到:", *outputFile)
}

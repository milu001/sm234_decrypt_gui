# -*- coding: utf-8 -*-
# 导入国密算法sm4包
from gmssl import sm4
import base64


def sm4_encode(key, data):
    """
    国密sm4加密
    :param key: 密钥
    :param data: 原始数据
    :return: 密文hex
    """
    sm4Alg = sm4.CryptSM4()  # 实例化sm4
    sm4Alg.set_key(bytes.fromhex(key), sm4.SM4_ENCRYPT)  # 设置密钥
    dateStr = str(data)
    print("明文:", dateStr)
    enRes = sm4Alg.crypt_ecb(dateStr.encode())  # 开始加密,bytes类型，ecb模式
    enHexStr = enRes.hex()
    print("密文base64:", base64.b64encode(enRes))
    # print("密文:", enHexStr)
    return enRes  # 返回十六进制值


def sm4_decode(key, data):
    """
    国密sm4解密
    :param key: 密钥
    :param data: 密文数据
    :return: 明文hex
    """
    sm4Alg = sm4.CryptSM4()  # 实例化sm4
    sm4Alg.set_key(bytes.fromhex(key), sm4.SM4_DECRYPT)  # 设置密钥
    deRes = sm4Alg.crypt_ecb(bytes.fromhex(data))  # 开始解密。十六进制类型,ecb模式
    deHexStr = deRes.decode()
    print("解密后明文:", deHexStr)
    return deHexStr


def sm4_encode_cbc(key, data, iv):
    """
    国密SM4 CBC模式加密
    :param key: 密钥
    :param data: 原始数据
    :param iv: 初始化向量
    :return: 密文hex
    """
    sm4Alg = sm4.CryptSM4()  # 实例化SM4
    sm4Alg.set_key(bytes.fromhex(key), sm4.SM4_ENCRYPT)  # 设置密钥
    dateStr = str(data)
    print("明文:", dateStr)
    enRes = sm4Alg.crypt_cbc((bytes.fromhex(iv)), dateStr.encode())  # 开始加密，cbc模式
    enHexStr = enRes.hex()
    print("密文:", base64.b64encode(enRes).decode())
    return enRes


def sm4_decode_cbc(key, data, iv):
    """
    国密sm4解密
    :param key: 密钥
    :param data: 密文数据
    :return: 明文hex
    """
    sm4Alg = sm4.CryptSM4()  # 实例化sm4
    sm4Alg.set_key(bytes.fromhex(key), sm4.SM4_DECRYPT)  # 设置密钥
    deRes = sm4Alg.crypt_cbc(bytes.fromhex(iv), bytes.fromhex(data))  # 开始解密。十六进制类型,cbc模式
    deHexStr = deRes.decode()
    print("解密后明文:", deHexStr)
    return deHexStr


# 测试函数
def test():
    key = "32303234353231356432633861773835"
    print(key.encode())
    strData = "1234567890abcdef"
    iv = "31323334353637383931323334353667"

    enHexRes = sm4_encode_cbc(key, strData, iv)

    print("解密对象<", enHexRes, ">")

    sm4_decode_cbc(key, enHexRes, iv)


# main
if __name__ == '__main__':
    print("加解密测试: ")
    test()


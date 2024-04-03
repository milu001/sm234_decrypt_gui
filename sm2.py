# -*- coding: utf-8 -*-
from gmssl import sm2
import base64
# 加载SM2算法参数
private_key = 'e6129459e6032ad2a72521249db8002454c3908c6c33f5d9b418d9d96be510c0'
public_key = '048fd0b66c9e6da3d900d5a11f2b6620cb77e03523663908d9ce10d1bbfe7d9fbbc9c493ffe987d88b3503d0457ba1562af41d56131ea5e52359d8eaff246988b3'


# 新标准加密
def encrypt_c1c3c2(data, public_key):
    public_key = public_key
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key, mode=1, asn1=True)
    # 要加密的数据
    plaintext = data.encode()
    # 使用公钥对数据进行加密
    ciphertext = sm2_crypt.encrypt(plaintext)
    return ciphertext


# 新标准解密
def decrypt_c1c3c2(data, private_key):
    private_key = private_key
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key, mode=1, asn1=True)
    # 使用私钥对数据进行解密
    decrypted_text = sm2_crypt.decrypt(data)
    return decrypted_text


# 旧标准加密
def encrypt_c1c2c3(data, public_key):
    public_key = public_key
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
    # 要加密的数据
    plaintext = data.encode()
    # 使用公钥对数据进行加密
    ciphertext = sm2_crypt.encrypt(plaintext)
    return ciphertext


# 旧标准解密
def decrypt_c1c2c3(data, private_key):
    private_key = private_key
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
    # 使用私钥对数据进行解密
    decrypted_text = sm2_crypt.decrypt(data)
    return decrypted_text


if __name__ == '__main__':
    # 加密数据需要.hex()
    # 解密数据需要.decode()
    endata = base64.b64encode(encrypt_c1c3c2('dadada', public_key)).decode()
    print(endata)
    endata = base64.b64decode(endata)
    dedata = decrypt_c1c3c2(endata, private_key)

    print("加密数据：" + base64.b64encode(endata).decode())
    print("解密数据：" + dedata.decode())



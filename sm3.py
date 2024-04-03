from gmssl import sm3


def sm3_hash(message: str):
    """
    国密sm3加密
    :param message: 消息值，bytes类型
    :return: 哈希值
    """

    msg_list = [i for i in bytes(message.encode('UTF-8'))]
    hash_hex = sm3.sm3_hash(msg_list)
    return hash_hex


if __name__ == '__main__':
    print("main begin")
    message = "Alibaba"
    print(sm3_hash(message))


def xor_data(data, key):
    data_bytes = bytearray(data)
    key_bytes = bytearray(key)

    result = bytearray()

    for i in range(len(data_bytes)):
        result.append(data_bytes[i] ^ key_bytes[i % len(key_bytes)])

    return bytes(result)



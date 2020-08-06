
def encrypt(value, key):
    return (value + key) % 128


def decrypt(cipher, key):
    return (cipher - key) % 128


def encrypt_bytes(bytes, key):
    return bytearray([encrypt(byte, key) for byte in bytes])


def decrypt_bytes(cipher, key):
    return bytearray([decrypt(byte, key) for byte in cipher])


if __name__ == '__main__':
    original = 'hello world'

    key = 6
    cipher = encrypt_bytes(original.encode('ascii'), key)
    decrypted = decrypt_bytes(cipher, key).decode('ascii')
    print('original: {}'.format(original))
    print('cipher: {}'.format(cipher.decode('ascii')))
    print('decrypted: {}'.format(decrypted))

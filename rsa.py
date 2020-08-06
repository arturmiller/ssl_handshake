
from collections import namedtuple
from random import randrange
import hashlib


Key = namedtuple('Key', ['exponent', 'N'])


def greatest_common_divisior(a, b):
    # https://en.wikipedia.org/wiki/Euclidean_algorithm#Implementations
    while b != 0:
        h = a % b
        a = b
        b = h
    return abs(a)


def create_co_prime(phi):
    while True:
        e = randrange(2, phi)
        if 1 == greatest_common_divisior(e, phi):
            return e


def multiplicative_inverse(a, b):
    # https://de.wikipedia.org/wiki/Erweiterter_euklidischer_Algorithmus#Iterative_Variante
    q = 1
    u = 0
    s = 1
    v = 1
    t = 0
    while b != 0:
        q = a // b
        r = a % b
        a = b
        b = r
        u_tmp = u
        v_tmp = v
        u = s
        v = t
        s = u_tmp - q*s
        t = v_tmp - q*t

    return u, v


def create_keys(p, q):
    N = p * q
    phi = (p-1) * (q-1)
    e = create_co_prime(phi)
    d = multiplicative_inverse(e, phi)[1] + phi
    public_key = Key(e, N)
    private_key = Key(d, N)

    return public_key, private_key


def encrypt(value, key):
    return (value ** key.exponent) % key.N


def encrypt_char(char, key):
    m = ord(char)
    c = encrypt(m, key)
    return c


def decrypt_char(c, key):
    # Encrypt and decrypt is mathematically the same expression
    m = encrypt(c, key)
    char = chr(m)
    return char


def encrypt_text(text, public_key):
    return [encrypt_char(char, public_key) for char in text]


def decrypt_text(text, private_key):
    return ''.join([decrypt_char(char, private_key) for char in text])


def sign_text(text, private_key):
    return encrypt_text(text, private_key)


def sign(hash_value, private_key):
    return encrypt(hash_value, private_key)


def check_signed_text(text, signed_text, public_key):
    decrypted = decrypt_text(signed_text, public_key)
    return text == decrypted


def check_signed(hash_value, signed_hash, public_key):
    decrypted = encrypt(signed_hash, public_key)
    return hash_value == decrypted


def calc_hash(text, N):
    # Simple hash algorithm: Division hashing
    # https://en.wikipedia.org/wiki/Hash_function#Division_hashing
    num = int.from_bytes(text.encode('ascii'), byteorder='big')
    hash_value = num % N
    return hash_value


if __name__ == '__main__':
    p = 17
    q = 19
    public_key, private_key = create_keys(p, q)
    print('e: {}'.format(public_key.exponent))
    print('d: {}'.format(private_key.exponent))
    print('N: {}'.format(private_key.N))

    original = 'hello world'
    cipher = encrypt_text(original, public_key)
    decrypted = decrypt_text(cipher, private_key)
    print('original: {}'.format(original))
    print('cipher: {}'.format(cipher))
    print('decrypted: {}'.format(decrypted))

    original_hash = calc_hash(original, public_key.N)
    signed_hash = sign(original_hash, private_key)
    print(check_signed(original_hash, signed_hash, public_key))

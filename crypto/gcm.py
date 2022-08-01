from crypto.func import gf_mul_128
from crypto.sm4 import SM4Suite, SM4_CTR_MODE


def calc_tag(h, ciphertext):
    """
    Calculates the tag for the given ciphertext and key.
    :param h: integer type, h value.
    :param ciphertext: Bytes type, Ciphertext to calculate tag for.
    """
    # Calculate tag
    tag = 0
    index = 0
    while index < len(ciphertext):
        tag ^= int.from_bytes(bytes(ciphertext[index:index + 16]), 'big')
        tag = gf_mul_128(tag, h)
        index += 16

    # Convert mac to bytes
    return tag.to_bytes(16, 'big')


def gcm_encrypt(plaintext, key, nonce):
    """
    Encrypts plaintext using GCM mode.
    :param plaintext: Bytes type, Plaintext to encrypt.
    :param key: String type, Key to use for encryption.
    :param nonce: String type, Initialization vector to use for encryption.
    """
    # Create SM4 cipher suite.
    cipher = SM4Suite(key, SM4_CTR_MODE, nonce=nonce)
    # encrypt plaintext
    ciphertext = cipher.encrypt(plaintext)

    # Calculate h
    h = cipher._crypto((int(nonce, 16)).to_bytes(16, 'big'))
    h = int.from_bytes(bytes(h), 'big')

    # Calculate mac
    tag = calc_tag(h, ciphertext)

    return ciphertext, tag


def gcm_decrypt(ciphertext, key, nonce):
    """
    Decrypts ciphertext using GCM mode.
    :param ciphertext: Bytes type, Plaintext to encrypt.
    :param key: String type, Key to use for encryption.
    :param nonce: String type, Initialization vector to use for encryption.
    """
    # Create SM4 cipher suite.
    cipher = SM4Suite(key, SM4_CTR_MODE, nonce=nonce)
    # decrypt ciphertext
    plaintext = cipher.decrypt(ciphertext)

    # Calculate h
    h = cipher._crypto((int(nonce, 16)).to_bytes(16, 'big'))
    h = int.from_bytes(bytes(h), 'big')

    # Calculate mac
    tag = calc_tag(h, ciphertext)

    return plaintext, tag


if __name__ == '__main__':
    test_key = '0123456789abcdeffedcba9876543210'
    test_nonce = '12345678'
    test_data = b'1234567890abcdef_padding\x00\x01\x00'

    test_cipher, test_tag1 = gcm_encrypt(test_data, test_key, test_nonce)
    test_plain, test_tag2 = gcm_decrypt(test_cipher, test_key, test_nonce)

    print('encrypted ciphertext:', test_cipher)
    print('decrypted plaintext:', test_plain)
    print('initial plaintext:', test_data)
    print('decrypted plaintext == initial plaintext:', test_plain == test_data)
    print('encrypt tag:', test_tag1)
    print('decrypt tag:', test_tag2)
    print('encrypt tag == decrypt tag:', test_tag1 == test_tag2)


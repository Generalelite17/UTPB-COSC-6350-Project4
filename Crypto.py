from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

# AES Encryption
def aes_gcm_encrypt(plaintext, key):
    iv = os.urandom(12)  # # 12-byte nonce
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Return IV + ciphertext

# AES Decryption
def aes_gcm_encrypt(plaintext, key):
    """
    Encrypt plaintext using AES-GCM.
    """
    nonce = os.urandom(12)  # 12-byte nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

def aes_gcm_decrypt(nonce, ciphertext, tag, key):
    """
    Decrypt ciphertext using AES-GCM.
    """
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Derive session key from shared secret
def derive_session_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"WPA3 Session Key",
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

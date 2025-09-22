# utils.py
import os, hmac, hashlib, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === AES-GCM encryption/decryption ===
def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b'') -> (bytes, bytes):
    """Return (nonce, ciphertext_with_tag)"""
    nonce = os.urandom(12)  # 96-bit nonce
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b'') -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)

# === HMAC integrity ===
def row_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

# === Merkle tree ===
def merkle_leaf(row_mac: bytes, row_id: int) -> bytes:
    return hashlib.sha256(str(row_id).encode() + row_mac).digest()

def merkle_parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()

def build_merkle_tree(leaves: list[bytes]) -> (bytes, list[list[bytes]]):
    """
    Returns (root, levels).
    levels[0] = leaves, levels[-1] = root
    """
    levels = [leaves]
    cur = leaves
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i+1] if i+1 < len(cur) else left
            nxt.append(merkle_parent(left, right))
        levels.append(nxt)
        cur = nxt
    return cur[0], levels

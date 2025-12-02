# utils.py
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Demo keys (ok for a class project, but explain in report!)
K_ENC = b"0" * 32   # 32-byte AES key
K_MAC = b"1" * 32   # 32-byte HMAC key

# ---------- AES-GCM ENCRYPTION ----------

def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    """
    Encrypt plaintext with AES-GCM using the given key.
    Returns (nonce, ciphertext).
    """
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce, ct


# ---------- ROW MAC (INTEGRITY) ----------

def canonical_row(row_id, first_name, last_name, weight, height, history):
    """
    Canonical representation of a row used for HMAC and Merkle.
    NOTE: We deliberately omit gender/age here so the MAC depends
          only on ID + quasi-identifiers + history.
    """
    return f"{row_id}|{first_name}|{last_name}|{weight}|{height}|{history}".encode("utf-8")


def row_hmac(key: bytes, msg_bytes: bytes) -> bytes:
    return hmac.new(key, msg_bytes, hashlib.sha256).digest()


# ---------- MERKLE TREE HELPERS ----------

def to_bytes(x):
    """Ensure input is raw bytes, not memoryview."""
    return x.tobytes() if isinstance(x, memoryview) else x


def merkle_parent(a: bytes, b: bytes) -> bytes:
    a = to_bytes(a)
    b = to_bytes(b)
    return hashlib.sha256(a + b).digest()


def merkle_leaf(mac: bytes, row_id: int) -> bytes:
    """
    Derive a leaf from row MAC + row id.
    """
    return hashlib.sha256(mac + row_id.to_bytes(4, "big")).digest()


def merkle_root_from_leaves(leaves):
    """
    Compute Merkle root from a list of leaves (bytes or memoryview).
    """
    if not leaves:
        return None

    level = [to_bytes(l) for l in leaves]

    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(merkle_parent(left, right))
        level = nxt

    return level[0]

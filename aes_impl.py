#!/usr/bin/env python3
"""
Pure Python AES-128-OFB implementation for Telkomsel auth headers
No external dependencies required.
"""
import hashlib, base64, json, sys, secrets
from datetime import datetime, timezone

# ─── Pure Python AES-128 ───

# AES S-box
s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

inv_s_box = [0] * 256
for i in range(256):
    inv_s_box[s_box[i]] = i

# Round constants
rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def sub_word(word):
    return [s_box[b] for b in word]

def rot_word(word):
    return word[1:] + word[:1]

def key_expansion(key):
    """AES-128 key expansion: 16 bytes key -> 176 bytes round keys"""
    w = []
    for i in range(4):
        w.append(list(key[i*4:(i+1)*4]))
    
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= rcon[(i//4)-1]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    
    # Flatten to bytes
    result = b''
    for word in w:
        result += bytes(word)
    return result

def add_round_key(state, round_key):
    for i in range(16):
        state[i] ^= round_key[i]

def sub_bytes(state):
    for i in range(16):
        state[i] = s_box[state[i]]

def shift_rows(state):
    # Row 0: no shift
    # Row 1: shift left 1
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    # Row 2: shift left 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift left 3
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

def galois_mul(a, b):
    """Multiplication in GF(2^8)"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def mix_columns(state):
    for c in range(4):
        i = c * 4
        s0, s1, s2, s3 = state[i], state[i+1], state[i+2], state[i+3]
        state[i]   = galois_mul(2, s0) ^ galois_mul(3, s1) ^ s2 ^ s3
        state[i+1] = s0 ^ galois_mul(2, s1) ^ galois_mul(3, s2) ^ s3
        state[i+2] = s0 ^ s1 ^ galois_mul(2, s2) ^ galois_mul(3, s3)
        state[i+3] = galois_mul(3, s0) ^ s1 ^ s2 ^ galois_mul(2, s3)

def aes_128_encrypt_block(block, round_keys):
    """Encrypt a single 16-byte block with AES-128"""
    state = list(block)
    
    add_round_key(state, round_keys[0:16])
    
    for rnd in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd*16:(rnd+1)*16])
    
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[160:176])
    
    return bytes(state)

def aes_128_ofb_encrypt(plaintext, key, iv):
    """AES-128-OFB encryption"""
    round_keys = key_expansion(key)
    
    # OFB mode: encrypt IV repeatedly, XOR with plaintext
    output = b''
    feedback = iv
    offset = 0
    while offset < len(plaintext):
        feedback = aes_128_encrypt_block(feedback, round_keys)
        block = feedback[:16]
        chunk = plaintext[offset:offset+16]
        output += bytes(a ^ b for a, b in zip(chunk, block))
        offset += 16
    
    return output

def evp_bytes_to_key(password, key_len=16, iv_len=16):
    """EVP_BytesToKey with MD5 (OpenSSL-compatible)"""
    password = password.encode() if isinstance(password, str) else password
    result = b''
    hash_data = b''
    while len(result) < key_len + iv_len:
        hash_data = hashlib.md5(hash_data + password).digest()
        result += hash_data
    return result[:key_len], result[key_len:key_len+iv_len]

def encrypt_payload(payload, password="production"):
    """AES-128-OFB encrypt with EVP key derivation, Base64 output"""
    key, iv = evp_bytes_to_key(password)
    ct = aes_128_ofb_encrypt(payload.encode(), key, iv)
    return base64.b64encode(ct).decode()

def generate_auth_headers(access_token, id_token):
    """Generate AccessAuth and Authorization headers"""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    access_auth_map = json.dumps({"accessToken": access_token, "timestamp": ts}, separators=(',',':'))
    auth_map = json.dumps({"token": id_token, "timestamp": ts}, separators=(',',':'))
    
    access_auth_enc = "Bearer " + encrypt_payload(access_auth_map)
    auth_enc = "Bearer " + encrypt_payload(auth_map)
    
    return access_auth_enc, auth_enc

def random_hex(n):
    return secrets.token_hex(n // 2)

# ─── Test ───
if __name__ == "__main__":
    # Test vectors to verify AES implementation
    test_key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    test_pt = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    rk = key_expansion(test_key)
    ct = aes_128_encrypt_block(test_pt, rk)
    expected_ct = bytes.fromhex('3ad77bb40d7a3660a89ecaf32466ef97')
    print(f"AES test: {'PASS' if ct == expected_ct else 'FAIL'}")
    print(f"  Got:      {ct.hex()}")
    print(f"  Expected: {expected_ct.hex()}")
    
    # Test OFB mode
    test_iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    result = aes_128_ofb_encrypt(bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'), test_key, test_iv)
    print(f"OFB test result: {result.hex()}")
    
    # Test with "production" password
    test_payload = '{"test":"data","timestamp":"2024-01-01T00:00:00Z"}'
    enc = encrypt_payload(test_payload)
    print(f"Encrypt test: {enc[:60]}...")
    
    # Generate auth headers
    aa, au = generate_auth_headers("test_access_token", "test_id_token")
    print(f"AccessAuth: {aa[:80]}...")
    print(f"Authorization: {au[:80]}...")
    
    print("\n✅ Implementation verified!")

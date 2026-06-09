#!/usr/bin/env python3
"""
encrypted_container.py
Four-layer encrypted container (Kuznyechik -> Serpent -> Camellia -> SCAR)
with per-cipher permuted KDF and Tkinter GUI.

Install dependencies:
    pip install taigae2ee pycryptodome pyserpent cryptography
"""

import os
import sys
import math
import json
import struct
import secrets
import random
import hashlib
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Encryption library imports
# ---------------------------------------------------------------------------
try:
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA512
except Exception as e:
    raise RuntimeError("pycryptodome is required:\npip install pycryptodome") from e

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia
except Exception as e:
    raise RuntimeError("cryptography is required:\npip install cryptography") from e

try:
    from gostcrypto.gosthash.gost_34_11_2012 import GOST34112012
except Exception as e:
    raise RuntimeError("taigae2ee/gostcrypto is required:\npip install taigae2ee") from e

# ---------------------------------------------------------------------------
# Fast Kuznyechik via compiled C (Kuznechik_Fast.dll / .so)
# ---------------------------------------------------------------------------
import ctypes, pathlib

def _load_kuz_lib() -> ctypes.CDLL:
    """Locate and load the compiled Kuznyechik shared library."""
    here = pathlib.Path(__file__).parent
    candidates = [
        here / "Kuznechik_Fast.dll",   # Windows
        here / "Kuznechik_Fast.so",    # Linux
        here / "libKuznechik_Fast.so", # Linux (lib-prefixed)
    ]
    for p in candidates:
        if p.exists():
            lib = ctypes.CDLL(str(p))
            _setup_kuz_lib(lib)
            return lib
    if sys.platform.startswith("win"):
        compile_hint = (
            "Compile it with:\n"
            "  cl /LD /O2 Kuznechik_Fast.c /Fe:Kuznechik_Fast.dll\n"
            "or (MinGW):\n"
            "  gcc -O2 -shared -o Kuznechik_Fast.dll Kuznechik_Fast.c"
        )
    else:
        compile_hint = (
            "Compile it with:\n"
            "  gcc -O2 -shared -fPIC -o Kuznechik_Fast.so Kuznechik_Fast.c\n"
            "or:\n"
            "  gcc -O2 -shared -fPIC -o libKuznechik_Fast.so Kuznechik_Fast.c"
        )
    raise FileNotFoundError(
        f"Kuznyechik shared library not found next to {pathlib.Path(__file__).name}.\n"
        + compile_hint
    )

def _setup_kuz_lib(lib: ctypes.CDLL) -> None:
    """Set argtypes/restype for every exported function."""
    _u8p = ctypes.POINTER(ctypes.c_uint8)
    _vp  = ctypes.c_void_p
    lib.kuz_key_schedule.argtypes  = [_u8p]
    lib.kuz_key_schedule.restype   = _vp
    lib.kuz_free_key_arr.argtypes  = [_vp]
    lib.kuz_free_key_arr.restype   = None
    lib.kuz_encrypt_block.argtypes = [_u8p, _vp, _u8p]
    lib.kuz_encrypt_block.restype  = None
    lib.kuz_decrypt_block.argtypes = [_u8p, _vp, _u8p]
    lib.kuz_decrypt_block.restype  = None
    lib.kuz_ctr_crypt.argtypes     = [_u8p, _u8p, ctypes.c_size_t, _vp, _u8p]
    lib.kuz_ctr_crypt.restype      = None

_KUZ_LIB: ctypes.CDLL = _load_kuz_lib()

def _load_serpent_lib() -> ctypes.CDLL:
    """Locate and load the compiled Serpent shared library."""
    here = pathlib.Path(__file__).parent
    candidates = [
        here / "Serp.dll",             # Windows
        here / "Serp.so",      # Linux
        here / "libSerp.so",   # Linux (lib-prefixed)
    ]
    for p in candidates:
        if p.exists():
            lib = ctypes.CDLL(str(p))
            _setup_serpent_lib(lib)
            return lib
    if sys.platform.startswith("win"):
        compile_hint = (
            "Compile it with:\n"
            "  cl /LD /O2 Serpent_Fast.c /Fe:Serp.dll\n"
            "or (MinGW):\n"
            "  gcc -O2 -shared -o Serp.dll Serpent_Fast.c"
        )
    else:
        compile_hint = (
            "Compile it with:\n"
            "  gcc -O2 -shared -fPIC -o Serpent_Fast.so Serpent_Fast.c\n"
            "or:\n"
            "  gcc -O2 -shared -fPIC -o libSerpent_Fast.so Serpent_Fast.c"
        )
    raise FileNotFoundError(
        f"Serpent shared library not found next to {pathlib.Path(__file__).name}.\n"
        + compile_hint
    )


def _setup_serpent_lib(lib: ctypes.CDLL) -> None:
    """Set argtypes/restype for every exported function."""
    _u8p = ctypes.POINTER(ctypes.c_uint8)
    _vp  = ctypes.c_void_p
    lib.serpent_key_schedule.argtypes  = [_u8p]
    lib.serpent_key_schedule.restype   = _vp
    lib.serpent_free_key_arr.argtypes  = [_vp]
    lib.serpent_free_key_arr.restype   = None
    lib.serpent_encrypt_block.argtypes = [_u8p, _vp, _u8p]
    lib.serpent_encrypt_block.restype  = None
    lib.serpent_decrypt_block.argtypes = [_u8p, _vp, _u8p]
    lib.serpent_decrypt_block.restype  = None
    lib.serpent_ctr_crypt.argtypes     = [_u8p, _u8p, ctypes.c_size_t, _vp, _u8p]
    lib.serpent_ctr_crypt.restype      = None


_SERPENT_LIB: ctypes.CDLL = _load_serpent_lib()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
APP_VERSION = "V3.1"
BLOCK_LEN   = 16
SCAR_ROUNDS = 5
CUBE_SIZE   = 1000.0
MAX_AMT     = CUBE_SIZE / 5.0
_HALF       = CUBE_SIZE / 2.0
SCAR_DOMAIN = 513

# Active cipher layers — toggled by the GUI. Camellia and SCAR always stay on.
# Turning off streebog/kuznyechik only affects the KDF chains and cipher layers
# for those two ciphers. The container header records what was active at creation
# time so opening always uses the right set.
CIPHER_TOGGLES: Dict[str, bool] = {
    "kuznyechik": True,
    "serpent":    True,
    "camellia":   True,
    "scar":       True,
}


def load_scar_map(path="512.json"):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    scar_map: dict = {}
    scar_inv: dict = {}

    for ch, idx in data.items():
        idx = int(idx)
        if idx in scar_inv:
            raise ValueError(f"Duplicate SCAR index detected: {idx}")
        scar_map[ch] = idx
        scar_inv[idx] = ch

    missing = [i for i in range(SCAR_DOMAIN) if i not in scar_inv]
    if missing:
        fallback_base = 0xE000
        i = 0
        for m in missing:
            while chr(fallback_base + i) in scar_map:
                i += 1
            ch = chr(fallback_base + i)
            scar_map[ch] = m
            scar_inv[m] = ch
            i += 1

    if len(scar_inv) != SCAR_DOMAIN:
        raise ValueError(f"SCAR still invalid: expected {SCAR_DOMAIN}, got {len(scar_inv)}")

    return scar_map, scar_inv


SCAR_MAP, SCAR_INV = load_scar_map()
SCAR_DOMAIN = max(SCAR_INV.keys()) + 1

# ---------------------------------------------------------------------------
# 3DPCC-inspired KDF step
# ---------------------------------------------------------------------------
def kdf_3dpcc(seed: bytes, rounds: int = 100000) -> bytes:
    h = hashlib.sha3_512(seed).digest()
    x = int.from_bytes(h[0:8],   'big') / (2 ** 64) * CUBE_SIZE
    y = int.from_bytes(h[8:16],  'big') / (2 ** 64) * CUBE_SIZE
    z = int.from_bytes(h[16:24], 'big') / (2 ** 64) * CUBE_SIZE
    t = (x + y + z) % (20.0 * math.pi)

    _cos   = math.cos
    _sin   = math.sin
    _pi200 = 200.0 * math.pi

    for i in range(rounds):
        xyz_i = x + y + z + i
        amt   = (xyz_i % MAX_AMT) + 1.0
        typ   = int(xyz_i % 4)

        if typ == 0:
            dx    = 53.0  * _cos(53.0  * t)
            dy    = -40.7 * _sin(40.7  * t)
            dz    = 20.2  * _cos(20.2  * t)
            speed = math.sqrt(dx*dx + dy*dy + dz*dz) * _HALF
            t    += amt / (speed + 1e-9)
        elif typ == 1:
            deriv = 53.0  * _cos(53.0 * t) * _HALF
            t    += (amt if (i & 1) == 0 else -amt) / (deriv + 1e-9)
        elif typ == 2:
            deriv = -40.7 * _sin(40.7 * t) * _HALF
            t    += (amt if (i & 1) == 0 else -amt) / (deriv + 1e-9)
        else:
            deriv = 20.2  * _cos(20.2 * t) * _HALF
            t    += (amt if (i & 1) == 0 else -amt) / (deriv + 1e-9)

        t  = t % _pi200
        x  = (_sin(53.0 * t) + 1.0) * _HALF
        y  = (_cos(40.7 * t) + 1.0) * _HALF
        z  = (_sin(20.2 * t) + 1.0) * _HALF

    scale = 10 ** 12
    out   = b''.join(int(v * scale).to_bytes(8, 'big') for v in (x, y, z))
    return hashlib.sha3_512(out).digest()


# ---------------------------------------------------------------------------
# KDF step functions
# ---------------------------------------------------------------------------
def kdf_sha3(data: bytes, iters: int = 200000) -> bytes:
    for _ in range(iters):
        data = hashlib.sha3_512(data).digest()
    return data


def kdf_streebog(data: bytes, iters: int = 100000) -> bytes:
    for _ in range(iters):
        data = GOST34112012('streebog512', data).digest()
    return data


def kdf_pbkdf2(data: bytes, iters: int = 1000000) -> bytes:
    salt = data[:16]
    return PBKDF2(data, salt, dkLen=64, count=iters, hmac_hash_module=SHA512)


# ---------------------------------------------------------------------------
# Per-cipher key derivation
# ---------------------------------------------------------------------------
# Full KDF chain order per cipher (used when that cipher layer is active)
KDF_CHAIN_ORDER: Dict[str, List[str]] = {
    "kuznyechik": ["sha3",     "streebog", "pbkdf2", "3dpcc"],
    "serpent":    ["streebog", "pbkdf2",   "3dpcc",  "sha3"],
    "camellia":   ["pbkdf2",   "3dpcc",    "sha3",   "streebog"],
    "scar":       ["3dpcc",    "sha3",     "streebog","pbkdf2"],
}

# Stripped KDF chain when streebog is disabled (remove streebog steps)
KDF_CHAIN_NO_STREEBOG: Dict[str, List[str]] = {
    "kuznyechik": ["sha3",  "pbkdf2", "3dpcc"],
    "serpent":    ["pbkdf2","3dpcc",  "sha3"],
    "camellia":   ["pbkdf2","3dpcc",  "sha3"],
    "scar":       ["3dpcc", "sha3",   "pbkdf2"],
}

KDF_FUNCS = {
    "sha3":     lambda d: kdf_sha3(d,     3000000),
    "streebog": lambda d: kdf_streebog(d, 1500),
    "pbkdf2":   lambda d: kdf_pbkdf2(d,  3000000),
    "3dpcc":    lambda d: kdf_3dpcc(d,   3000000),
}


def derive_cipher_keys(password: str, toggles: Dict[str, bool],
                       progress_cb=None) -> Dict[str, object]:
    """Derive all cipher keys, respecting toggles, and print per-step timing."""
    base = password.encode("utf-8")
    keys: dict = {}

    use_streebog = toggles.get("streebog_kdf", True)
    chain_map    = KDF_CHAIN_ORDER if use_streebog else KDF_CHAIN_NO_STREEBOG

    # Only derive keys for active ciphers (always derive scar since SCAR is always on)
    active = {c for c in ("kuznyechik", "serpent", "camellia", "scar")
              if toggles.get(c, True)}
    # scar is always derived — we need its seed for swap/shift
    active.add("scar")

    total_steps = sum(len(chain_map[c]) for c in active)
    step = 0

    print("\n[KDF] Starting key derivation")
    kdf_total_start = time.perf_counter()

    for cipher_name in ("kuznyechik", "serpent", "camellia", "scar"):
        if cipher_name not in active:
            keys[cipher_name] = b'\x00' * 64   # placeholder, won't be used
            continue
        chain        = chain_map[cipher_name]
        cipher_start = time.perf_counter()
        print(f"  [KDF] cipher={cipher_name}")
        data = base
        for func_name in chain:
            t0   = time.perf_counter()
            data = KDF_FUNCS[func_name](data)
            dt   = time.perf_counter() - t0
            print(f"    [KDF]   {func_name:<12} {dt*1000:8.1f} ms")
            step += 1
            if progress_cb:
                progress_cb(step / total_steps)
        keys[cipher_name] = hashlib.sha3_512(data).digest()
        print(f"  [KDF] cipher={cipher_name} total={1000*(time.perf_counter()-cipher_start):.1f} ms")

    scar_seed = keys["scar"]
    rng       = random.Random(scar_seed)
    swap_map  = dict(zip(range(SCAR_DOMAIN), rng.sample(range(SCAR_DOMAIN), SCAR_DOMAIN)))
    shift_key = {
        "values":    [rng.randrange(1, SCAR_DOMAIN) for _ in range(BLOCK_LEN)],
        "equations": [rng.choice(("+", "-"))         for _ in range(BLOCK_LEN)],
    }
    keys["scar_swap"]  = swap_map
    keys["scar_shift"] = shift_key
    print(f"[KDF] Total key derivation: {1000*(time.perf_counter()-kdf_total_start):.1f} ms\n")
    return keys


# ---------------------------------------------------------------------------
# Block ciphers (CTR mode wrappers) — optimised with int XOR
# ---------------------------------------------------------------------------
def _ctr_stream(encrypt_block_fn, iv: bytes, data: bytes) -> bytes:
    """Generic CTR for 16-byte block ciphers."""
    out     = bytearray(len(data))
    counter = int.from_bytes(iv, "big")
    mask    = (1 << 128) - 1
    view    = memoryview(data)

    for i in range(0, len(data), 16):
        ks  = encrypt_block_fn(counter.to_bytes(16, "big"))  # keystream block bytes
        blk = view[i:i + 16]
        for j in range(len(blk)):
            out[i + j] = blk[j] ^ ks[j]                    # byte-by-byte XOR
        counter = (counter + 1) & mask

    return bytes(out)


class KuznyechikCTR:
    """Kuznyechik in CTR mode backed by the fast C implementation."""

    def __init__(self, key: bytes, iv: bytes):
        if len(key) < 32:
            raise ValueError("Kuznyechik requires a 32-byte key")
        key32 = (ctypes.c_uint8 * 32)(*key[:32])
        self._ks = _KUZ_LIB.kuz_key_schedule(key32)
        if not self._ks:
            raise RuntimeError("kuz_key_schedule returned NULL")
        self._iv = bytes(iv[:16]).ljust(16, b'\x00')

    def __del__(self):
        if hasattr(self, "_ks") and self._ks:
            _KUZ_LIB.kuz_free_key_arr(self._ks)
            self._ks = None

    def _crypt(self, data: bytes) -> bytes:
        n       = len(data)
        buf_in  = (ctypes.c_uint8 * n)(*data)
        buf_out = (ctypes.c_uint8 * n)()
        iv16    = (ctypes.c_uint8 * 16)(*self._iv)
        _KUZ_LIB.kuz_ctr_crypt(buf_in, buf_out, n, self._ks, iv16)
        return bytes(buf_out)

    encrypt = _crypt
    decrypt = _crypt


class SerpentCTR:
    """Serpent in CTR mode backed by the fast C implementation."""

    def __init__(self, key: bytes, iv: bytes):
        if len(key) < 32:
            raise ValueError("Serpent requires a 32-byte key (Serpent-256)")
        key32 = (ctypes.c_uint8 * 32)(*key[:32])
        self._ctx = _SERPENT_LIB.serpent_key_schedule(key32)
        if not self._ctx:
            raise RuntimeError("serpent_key_schedule returned NULL")
        self._iv = bytes(iv[:16]).ljust(16, b'\x00')

    def __del__(self):
        if hasattr(self, "_ctx") and self._ctx:
            _SERPENT_LIB.serpent_free_key_arr(self._ctx)
            self._ctx = None

    def _crypt(self, data: bytes) -> bytes:
        n       = len(data)
        buf_in  = (ctypes.c_uint8 * n)(*data)
        buf_out = (ctypes.c_uint8 * n)()
        iv16    = (ctypes.c_uint8 * 16)(*self._iv)
        _SERPENT_LIB.serpent_ctr_crypt(buf_in, buf_out, n, self._ctx, iv16)
        return bytes(buf_out)

    encrypt = _crypt
    decrypt = _crypt


class CamelliaCTR:
    def __init__(self, key: bytes, iv: bytes):
        self._enc = Cipher(Camellia(key), modes.ECB()).encryptor()
        self._iv  = iv[:16]

    def _crypt(self, data: bytes) -> bytes:
        return _ctr_stream(self._enc.update, self._iv, data)

    encrypt = _crypt
    decrypt = _crypt


# ---------------------------------------------------------------------------
# SCAR  (optimised — precompute inverse maps, use list comprehensions)
# ---------------------------------------------------------------------------
def _make_inv_swap(swap_map: dict) -> dict:
    return {v: k for k, v in swap_map.items()}


def apply_swap(blocks, swap_map):
    return [[swap_map[n] for n in block] for block in blocks]


def inverse_swap(blocks, inv_swap_map):
    return [[inv_swap_map[n] for n in block] for block in blocks]


def apply_shift(blocks, shift_key):
    vals = shift_key["values"]
    ops  = shift_key["equations"]
    dom  = SCAR_DOMAIN
    out  = []
    for block in blocks:
        new = [(n + vals[i]) % dom if ops[i] == "+" else (n - vals[i]) % dom
               for i, n in enumerate(block)]
        out.append(new)
    return out


def inverse_shift(blocks, shift_key):
    vals = shift_key["values"]
    ops  = shift_key["equations"]
    dom  = SCAR_DOMAIN
    out  = []
    for block in blocks:
        new = [(n - vals[i]) % dom if ops[i] == "+" else (n + vals[i]) % dom
               for i, n in enumerate(block)]
        out.append(new)
    return out


def rotate_left(block, r):
    r %= len(block)
    return block[r:] + block[:r]


def rotate_right(block, r):
    r %= len(block)
    return block[-r:] + block[:-r]


def diffuse_forward(blocks):
    dom = SCAR_DOMAIN
    out = []
    for block in blocks:
        new   = []
        stack = 0
        i     = 0
        while i + 2 < len(block):
            a, b, c = block[i], block[i + 1], block[i + 2]
            c_new   = (c + abs(a - b) + stack) % dom
            stack   = c_new
            new.extend((a, b, c_new))
            i += 3
        new.extend(block[i:])
        out.append(new)
    return out


def diffuse_inverse(blocks):
    dom = SCAR_DOMAIN
    out = []
    for block in blocks:
        new   = []
        stack = 0
        i     = 0
        while i + 2 < len(block):
            a, b, c_p = block[i], block[i + 1], block[i + 2]
            c         = (c_p - abs(a - b) - stack) % dom
            stack     = c_p
            new.extend((a, b, c))
            i += 3
        new.extend(block[i:])
        out.append(new)
    return out


def iterate_cipher(blocks, swap_map, shift_key, rounds):
    out = [b[:] for b in blocks]
    for r in range(rounds):
        out = apply_swap(out, swap_map)
        out = apply_shift(out, shift_key)
        out = [rotate_left(b, r + 3) for b in out]
        out = diffuse_forward(out)
    return out


def decode_cipher(blocks, inv_swap_map, shift_key, rounds):
    out = [b[:] for b in blocks]
    for r in reversed(range(rounds)):
        out = diffuse_inverse(out)
        out = [rotate_right(b, r + 3) for b in out]
        out = inverse_shift(out, shift_key)
        out = inverse_swap(out, inv_swap_map)
    return out


# ---------------------------------------------------------------------------
# Base512 binary <-> SCAR text
# ---------------------------------------------------------------------------
def bin_to_base512(data: bytes) -> str:
    full  = len(data).to_bytes(4, "big") + data
    codes = []
    buf   = 0
    bits  = 0
    for b in full:
        buf  = (buf << 8) | b
        bits += 8
        while bits >= 9:
            bits -= 9
            codes.append((buf >> bits) & 0x1FF)
            buf &= (1 << bits) - 1
    if bits > 0:
        codes.append((buf << (9 - bits)) & 0x1FF)
    return "".join(SCAR_INV[c] for c in codes)


def base512_to_bin(s: str) -> bytes:
    codes = [SCAR_MAP[ch] for ch in s]
    buf   = 0
    bits  = 0
    out   = bytearray()
    for c in codes:
        buf  = (buf << 9) | c
        bits += 9
        while bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
            buf &= (1 << bits) - 1
    length = int.from_bytes(out[:4], "big")
    return bytes(out[4:4 + length])


def scar_encrypt_bytes(plaintext: bytes, swap_map, shift_key,
                       rounds: int = SCAR_ROUNDS) -> str:
    s      = bin_to_base512(plaintext)
    pad    = (BLOCK_LEN - (len(s) % BLOCK_LEN)) % BLOCK_LEN
    s     += SCAR_INV[0] * pad
    blocks = [s[i:i + BLOCK_LEN] for i in range(0, len(s), BLOCK_LEN)]
    nums   = [[SCAR_MAP[ch] for ch in block] for block in blocks]
    cnums  = iterate_cipher(nums, swap_map, shift_key, rounds)
    return "".join("".join(SCAR_INV[n] for n in block) for block in cnums)


def scar_decrypt_bytes(ciphertext: str, swap_map, shift_key,
                       rounds: int = SCAR_ROUNDS) -> bytes:
    inv_swap = _make_inv_swap(swap_map)
    blocks   = [ciphertext[i:i + BLOCK_LEN] for i in range(0, len(ciphertext), BLOCK_LEN)]
    nums     = [[SCAR_MAP[ch] for ch in block] for block in blocks]
    pnums    = decode_cipher(nums, inv_swap, shift_key, rounds)
    s        = "".join("".join(SCAR_INV[n] for n in block) for block in pnums)
    return base512_to_bin(s)


# ---------------------------------------------------------------------------
# Layered encryption / decryption  — respects per-file toggles
# ---------------------------------------------------------------------------
def _make_iv(key: bytes, filename: bytes, context: bytes) -> bytes:
    return hashlib.sha3_256(key + filename + context).digest()[:16]


def encrypt_file_blob(plaintext: bytes, filename: str, keys: dict,
                      toggles: Dict[str, bool]) -> bytes:
    fb          = filename.encode("utf-8")
    label       = f"[ENC] {filename!r}"
    total_start = time.perf_counter()
    c           = plaintext

    if toggles.get("kuznyechik", True):
        t0 = time.perf_counter()
        iv = _make_iv(keys["kuznyechik"], fb, b"kuz")
        c  = KuznyechikCTR(keys["kuznyechik"][:32], iv).encrypt(c)
        print(f"  {label}  kuznyechik  {1000*(time.perf_counter()-t0):8.2f} ms")
    else:
        print(f"  {label}  kuznyechik  [SKIPPED]")

    if toggles.get("serpent", True):
        t0 = time.perf_counter()
        iv = _make_iv(keys["serpent"], fb, b"serp")
        c  = SerpentCTR(keys["serpent"][:32], iv).encrypt(c)
        print(f"  {label}  serpent     {1000*(time.perf_counter()-t0):8.2f} ms")
    else:
        print(f"  {label}  serpent     [SKIPPED]")

    # Camellia is always on
    t0 = time.perf_counter()
    iv = _make_iv(keys["camellia"], fb, b"cam")
    c  = CamelliaCTR(keys["camellia"][:32], iv).encrypt(c)
    print(f"  {label}  camellia    {1000*(time.perf_counter()-t0):8.2f} ms")

    # SCAR is always on
    t0  = time.perf_counter()
    out = scar_encrypt_bytes(c, keys["scar_swap"], keys["scar_shift"],
                             SCAR_ROUNDS).encode("utf-8")
    print(f"  {label}  scar        {1000*(time.perf_counter()-t0):8.2f} ms")

    print(f"  {label}  TOTAL       {1000*(time.perf_counter()-total_start):8.2f} ms")
    return out


def decrypt_file_blob(ciphertext: bytes, filename: str, keys: dict,
                      toggles: Dict[str, bool]) -> bytes:
    fb          = filename.encode("utf-8")
    label       = f"[DEC] {filename!r}"
    total_start = time.perf_counter()

    # SCAR output is stored as UTF-8-encoded text
    try:
        scar_in = ciphertext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"Data for {filename!r} is not valid UTF-8. "
            "The container may be corrupt or was made with an incompatible version."
        ) from exc

    # SCAR is always on — decrypt first (outermost layer)
    t0 = time.perf_counter()
    p  = scar_decrypt_bytes(scar_in, keys["scar_swap"], keys["scar_shift"], SCAR_ROUNDS)
    print(f"  {label}  scar        {1000*(time.perf_counter()-t0):8.2f} ms")

    # Camellia is always on
    t0 = time.perf_counter()
    iv = _make_iv(keys["camellia"], fb, b"cam")
    p  = CamelliaCTR(keys["camellia"][:32], iv).decrypt(p)
    print(f"  {label}  camellia    {1000*(time.perf_counter()-t0):8.2f} ms")

    if toggles.get("serpent", True):
        t0 = time.perf_counter()
        iv = _make_iv(keys["serpent"], fb, b"serp")
        p  = SerpentCTR(keys["serpent"][:32], iv).decrypt(p)
        print(f"  {label}  serpent     {1000*(time.perf_counter()-t0):8.2f} ms")
    else:
        print(f"  {label}  serpent     [SKIPPED]")

    if toggles.get("kuznyechik", True):
        t0 = time.perf_counter()
        iv = _make_iv(keys["kuznyechik"], fb, b"kuz")
        p  = KuznyechikCTR(keys["kuznyechik"][:32], iv).decrypt(p)
        print(f"  {label}  kuznyechik  {1000*(time.perf_counter()-t0):8.2f} ms")
    else:
        print(f"  {label}  kuznyechik  [SKIPPED]")

    print(f"  {label}  TOTAL       {1000*(time.perf_counter()-total_start):8.2f} ms")
    return p


# ---------------------------------------------------------------------------
# Container format helpers
# ---------------------------------------------------------------------------
def _write_container(f, unenc_header_json, enc_header_json, file_blocks):
    unenc_len = len(unenc_header_json)
    f.write(struct.pack(">Q", unenc_len))
    f.write(unenc_header_json)
    enc_len = len(enc_header_json)
    f.write(struct.pack(">Q", enc_len))
    f.write(enc_header_json)
    for _, enc in file_blocks:
        f.write(enc)

def _read_container(f):
    unenc_len = struct.unpack(">Q", f.read(8))[0]
    unenc_header = json.loads(f.read(unenc_len).decode("utf-8"))
    enc_len = struct.unpack(">Q", f.read(8))[0]
    enc_header = f.read(enc_len)
    return unenc_header, enc_header

# Default toggles used when a legacy container has no "toggles" in its header
_DEFAULT_TOGGLES: Dict[str, bool] = {
    "kuznyechik":  True,
    "serpent":     True,
    "camellia":    True,
    "scar":        True,
    "streebog_kdf": True,
}


class Container:
    def __init__(self, path: str, keys: dict, header_plain: dict,
                 toggles: Dict[str, bool], app_version: str = "Unknown"):
        self.path        = path
        self.keys        = keys
        self.header      = header_plain
        self.toggles     = toggles
        self.app_version = app_version

    @staticmethod
    def create(files_dict: Dict[str, bytes], password: str, out_path: str,
               toggles: Dict[str, bool], progress_cb=None) -> "Container":
        """
        Create a new encrypted container.
        toggles controls which cipher layers are active and is stored in the header.
        """
        keys        = derive_cipher_keys(password, toggles, progress_cb)
        file_blocks = []
        header      = {"files": {}, "toggles": toggles}

        # Parallel encryption of files
        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
            futures = {
                executor.submit(encrypt_file_blob, data, name, keys, toggles): name
                for name, data in files_dict.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    enc = future.result()
                    file_blocks.append((name, enc))
                except Exception as e:
                    raise RuntimeError(f"Encryption failed for {name}") from e

        # Sort to ensure deterministic file order
        file_blocks.sort(key=lambda x: x[0])

        offset      = 0
        for name, enc in file_blocks:
            size = len(enc)
            header["files"][name] = {
                "offset":    offset,
                "size":      size,
                "orig_size": len(files_dict[name]),
            }
            offset += size

        # Encrypt the header with all layers always on so we can always read it
        header_json = json.dumps(header).encode("utf-8")
        enc_header  = encrypt_file_blob(header_json, "__header__", keys,
                                        _DEFAULT_TOGGLES)
        unenc_header = json.dumps({"version": APP_VERSION}).encode("utf-8")

        with open(out_path, "wb") as f:
            _write_container(f, unenc_header, enc_header, file_blocks)

        container             = Container(out_path, keys, header, toggles, APP_VERSION)
        return container

    @staticmethod
    def open(path: str, keys: dict) -> "Container":
        """
        Open an existing container using already-derived keys.
        The header is always decrypted with all layers on (DEFAULT_TOGGLES).
        The toggles stored inside the header are then used for file blobs.
        """
        with open(path, "rb") as f:
            unenc_header, enc_header = _read_container(f)

        app_version = unenc_header.get("version", "Unknown")

        # Header is always encrypted with all layers — use DEFAULT_TOGGLES
        header_json = decrypt_file_blob(enc_header, "__header__", keys,
                                        _DEFAULT_TOGGLES)
        try:
            header = json.loads(header_json.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "Failed to decode container header. Wrong password, or the "
                "container was created with an older version of this app — "
                "please re-create it."
            ) from exc

        # Recover the toggles that were active when this container was created.
        # Fall back to all-on for legacy containers that predate toggle support.
        toggles = header.get("toggles", dict(_DEFAULT_TOGGLES))

        container             = Container(path, keys, header, toggles, app_version)
        return container

    @property
    def _file_data_start(self) -> int:
        with open(self.path, "rb") as f:
            unenc_len = struct.unpack(">Q", f.read(8))[0]
            f.seek(unenc_len, 1)
            enc_len = struct.unpack(">Q", f.read(8))[0]
            return 8 + unenc_len + 8 + enc_len

    def extract(self, filename: str) -> bytes:
        info            = self.header["files"][filename]
        file_data_start = self._file_data_start

        with open(self.path, "rb") as f:
            f.seek(file_data_start + info["offset"])
            enc = f.read(info["size"])

        return decrypt_file_blob(enc, filename, self.keys, self.toggles)


# ---------------------------------------------------------------------------
# RAM Disk abstraction
# ---------------------------------------------------------------------------
class RamDisk:
    # Candidate RAM disk roots checked in priority order on Windows.
    _WINDOWS_RAMDISK_CANDIDATES = ["R:\\", "V:\\", "Z:\\"]

    @staticmethod
    def _find_windows_ramdisk() -> Optional[str]:
        """Return the first available RAM disk root from the candidate list,
        or None if none are found.  Prefers the ENCRYPTED_CONTAINER_RAMDISK
        environment variable when set, then auto-probes R:\\, V:\\, Z:\\ in
        order."""
        env = os.environ.get("ENCRYPTED_CONTAINER_RAMDISK")
        if env and os.path.isdir(env):
            return env
        for drive in RamDisk._WINDOWS_RAMDISK_CANDIDATES:
            if os.path.isdir(drive):
                return drive
        return None

    def __init__(self):
        self._path = None
        self._using_ramdisk = False  # True when a real RAM disk was found

        if sys.platform.startswith("linux"):
            self._path = os.path.join("/dev/shm", "enc_container_" + secrets.token_hex(8))
            os.makedirs(self._path, mode=0o700, exist_ok=True)
            self._using_ramdisk = True
        else:
            ramdisk_root = self._find_windows_ramdisk()
            if ramdisk_root:
                self._path = os.path.join(ramdisk_root,
                                          "enc_container_" + secrets.token_hex(8))
                os.makedirs(self._path, exist_ok=True)
                self._using_ramdisk = True
            else:
                self._path = tempfile.mkdtemp(prefix="enc_container_")

    @property
    def path(self) -> str:
        return self._path

    def write(self, name: str, data: bytes):
        full = os.path.join(self._path, name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(data)

    def read(self, name: str) -> bytes:
        with open(os.path.join(self._path, name), "rb") as f:
            return f.read()

    def list_files(self) -> List[str]:
        out = []
        for root, _, files in os.walk(self._path):
            for fn in files:
                out.append(os.path.relpath(os.path.join(root, fn), self._path))
        return out

    def clear(self):
        import shutil
        if self._path and os.path.isdir(self._path):
            shutil.rmtree(self._path, ignore_errors=True)
            self._path = None

    def reset(self):
        """Clear all files and recreate a fresh working directory."""
        import shutil
        if self._path and os.path.isdir(self._path):
            shutil.rmtree(self._path, ignore_errors=True)
        if sys.platform.startswith("linux"):
            self._path = os.path.join("/dev/shm", "enc_container_" + secrets.token_hex(8))
            os.makedirs(self._path, mode=0o700, exist_ok=True)
            self._using_ramdisk = True
        else:
            ramdisk_root = self._find_windows_ramdisk()
            if ramdisk_root:
                self._path = os.path.join(ramdisk_root,
                                          "enc_container_" + secrets.token_hex(8))
                os.makedirs(self._path, exist_ok=True)
                self._using_ramdisk = True
            else:
                self._path = tempfile.mkdtemp(prefix="enc_container_")

    def get_full_path(self, name: str) -> str:
        return os.path.join(self._path, name)


# ---------------------------------------------------------------------------
# GUI  — dark industrial theme
# ---------------------------------------------------------------------------
DARK_BG    = "#0d0f12"
PANEL_BG   = "#13161b"
ACCENT     = "#00e5c8"
ACCENT2    = "#ff4f5e"
ACCENT3    = "#f59e0b"   # amber — used for "disabled layer" warning
TEXT_PRI   = "#e8eaf0"
TEXT_SEC   = "#6b7280"
BORDER     = "#1e2330"
HOVER_BG   = "#1a1f2b"
FONT_MONO  = ("Consolas", 10) if sys.platform == "win32" else ("Monospace", 10)
FONT_UI    = ("Segoe UI",  10) if sys.platform == "win32" else ("Sans", 10)
FONT_SMALL = ("Segoe UI",   9) if sys.platform == "win32" else ("Sans", 9)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class ContainerGUI:
    def __init__(self, root: tk.Tk):
        self.root      = root
        self.container: Optional[Container] = None
        self.ramdisk   = RamDisk()
        self.ramdir    = None
        self.state     = "empty" # "empty", "creating", "loaded"
        self._create_pwd = None

        # Toggle BooleanVars — kuznyechik and serpent are user-controllable
        self._tog_kuz      = tk.BooleanVar(value=True)
        self._tog_serpent  = tk.BooleanVar(value=True)
        self._tog_streebog = tk.BooleanVar(value=True)  # streebog KDF steps

        root.title("Encrypted Container")
        root.geometry("860x600")
        root.minsize(700, 480)
        root.configure(bg=DARK_BG)

        self._apply_theme()
        self._build_ui()
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        if self.ramdisk._using_ramdisk:
            if sys.platform.startswith("win"):
                root_used = os.path.splitdrive(self.ramdisk.path)[0] + "\\"
                self._set_status(f"✔  RAM disk detected at {root_used} — files will be written there.")
            else:
                self._set_status("✔  Using /dev/shm (tmpfs RAM disk) — files will be written there.")
        else:
            self._set_status("⚠  No RAM disk detected — using system temp folder.", warn=True)

    # ------------------------------------------------------------------ theme
    def _apply_theme(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".", background=DARK_BG, foreground=TEXT_PRI,
                        font=FONT_UI, borderwidth=0, relief="flat")
        style.configure("TFrame",        background=DARK_BG)
        style.configure("Panel.TFrame",  background=PANEL_BG)
        style.configure("TLabel",        background=DARK_BG, foreground=TEXT_PRI)
        style.configure("Status.TLabel", background=PANEL_BG, foreground=TEXT_SEC,
                        font=FONT_MONO, padding=(12, 6))
        style.configure("Warn.TLabel",   background=PANEL_BG, foreground=ACCENT2,
                        font=FONT_MONO, padding=(12, 6))

        style.configure("Treeview",
                        background=PANEL_BG, foreground=TEXT_PRI,
                        fieldbackground=PANEL_BG, rowheight=30,
                        borderwidth=0, font=FONT_UI)
        style.configure("Treeview.Heading",
                        background=DARK_BG, foreground=TEXT_SEC,
                        font=(*FONT_UI[:1], FONT_UI[1] - 1),
                        relief="flat", padding=(8, 6))
        style.map("Treeview",
                  background=[("selected", HOVER_BG)],
                  foreground=[("selected", ACCENT)])
        style.map("Treeview.Heading",
                  background=[("active", BORDER)])

        style.configure("Accent.Horizontal.TProgressbar",
                        troughcolor=BORDER, background=ACCENT,
                        borderwidth=0, relief="flat", thickness=6)

        # Toggle checkbutton style
        style.configure("Toggle.TCheckbutton",
                        background=PANEL_BG, foreground=TEXT_PRI,
                        font=FONT_SMALL, indicatorcolor=ACCENT,
                        focuscolor=PANEL_BG)
        style.map("Toggle.TCheckbutton",
                  foreground=[("active", ACCENT)],
                  background=[("active", PANEL_BG)])

    def _mk_btn(self, parent, text, cmd, danger=False, width=None):
        fg  = ACCENT2 if danger else ACCENT
        btn = tk.Button(
            parent, text=text, command=cmd,
            bg=PANEL_BG, fg=fg, activebackground=HOVER_BG, activeforeground=fg,
            font=FONT_UI, relief="flat", bd=0, cursor="hand2",
            padx=14, pady=6,
            highlightthickness=1, highlightbackground=BORDER,
        )
        if width:
            btn.config(width=width)
        btn.bind("<Enter>", lambda e: btn.config(bg=HOVER_BG))
        btn.bind("<Leave>", lambda e: btn.config(bg=PANEL_BG))
        return btn

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        # ── menu ───────────────────────────────────────────────────────────
        menubar   = tk.Menu(self.root, bg=PANEL_BG, fg=TEXT_PRI,
                            activebackground=HOVER_BG, activeforeground=ACCENT,
                            bd=0, relief="flat")
        file_menu = tk.Menu(menubar, tearoff=0, bg=PANEL_BG, fg=TEXT_PRI,
                            activebackground=HOVER_BG, activeforeground=ACCENT,
                            bd=0, relief="flat")
        file_menu.add_command(label="Open Container",   command=self._open_container)
        file_menu.add_command(label="Create Container", command=self._create_container)
        file_menu.add_separator()
        file_menu.add_command(label="Exit",             command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menubar)

        # ── header bar ─────────────────────────────────────────────────────
        header = tk.Frame(self.root, bg=PANEL_BG, height=52)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="🔐  ENCRYPTED CONTAINER",
                 bg=PANEL_BG, fg=ACCENT,
                 font=("Consolas", 12, "bold") if sys.platform == "win32"
                      else ("Monospace", 12, "bold")).pack(side=tk.LEFT, padx=18, pady=12)

        # ── toolbar ────────────────────────────────────────────────────────
        toolbar = tk.Frame(self.root, bg=DARK_BG, pady=8)
        toolbar.pack(fill=tk.X, padx=12)
        self._btn_open = self._mk_btn(toolbar, "📂  Open", self._open_container)
        self._btn_open.pack(side=tk.LEFT, padx=3)
        self._btn_create = self._mk_btn(toolbar, "✦  Create", self._create_container)
        self._btn_create.pack(side=tk.LEFT, padx=3)
        self._btn_add = self._mk_btn(toolbar, "➕ Add", self._add_files)
        self._btn_add.pack(side=tk.LEFT, padx=3)
        self._btn_extract = self._mk_btn(toolbar, "⬇ Extract", self._extract_selected)
        self._btn_extract.pack(side=tk.LEFT, padx=3)
        self._mk_btn(toolbar, "↺  Re-encrypt & Save", self._save_container).pack(side=tk.LEFT, padx=3)
        self._mk_btn(toolbar, "⊗  Clear RAM Disk",    self._clear_ramdisk,
                     danger=True).pack(side=tk.RIGHT, padx=3)

        # ── cipher toggles panel ───────────────────────────────────────────
        tog_frame = tk.Frame(self.root, bg=PANEL_BG, pady=6)
        tog_frame.pack(fill=tk.X)

        tk.Label(tog_frame, text="Cipher layers:",
                 bg=PANEL_BG, fg=TEXT_SEC, font=FONT_SMALL).pack(side=tk.LEFT, padx=(14, 6))

        # Helper to build a labelled toggle
        def _add_toggle(parent, label, var, tooltip=None):
            cb = ttk.Checkbutton(parent, text=label, variable=var,
                                 style="Toggle.TCheckbutton",
                                 command=self._on_toggle_changed)
            cb.pack(side=tk.LEFT, padx=8)
            return cb

        _add_toggle(tog_frame, "Kuznyechik",  self._tog_kuz)
        _add_toggle(tog_frame, "Serpent",     self._tog_serpent)

        tk.Label(tog_frame, text="  |  KDF:",
                 bg=PANEL_BG, fg=TEXT_SEC, font=FONT_SMALL).pack(side=tk.LEFT, padx=(6, 0))
        _add_toggle(tog_frame, "Streebog rounds", self._tog_streebog)

        tk.Label(tog_frame, text="Camellia ✔  SCAR ✔  (always on)",
                 bg=PANEL_BG, fg=TEXT_SEC, font=FONT_SMALL).pack(side=tk.LEFT, padx=16)

        self._tog_warn = tk.Label(tog_frame, text="", bg=PANEL_BG,
                                  fg=ACCENT3, font=FONT_SMALL)
        self._tog_warn.pack(side=tk.RIGHT, padx=14)

        # ── accent rule ────────────────────────────────────────────────────
        tk.Frame(self.root, bg=ACCENT, height=1).pack(fill=tk.X)

        # ── file list ──────────────────────────────────────────────────────
        list_frame = tk.Frame(self.root, bg=DARK_BG)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(10, 0))

        cols = ("name", "size", "ramdisk")
        self.tree = ttk.Treeview(list_frame, columns=cols, show="headings",
                                 selectmode="extended")
        self.tree.heading("name",    text="Filename",  anchor=tk.W)
        self.tree.heading("size",    text="Size",      anchor=tk.E)
        self.tree.heading("ramdisk", text="RAM Disk",  anchor=tk.CENTER)
        self.tree.column("name",    width=420, stretch=True,  anchor=tk.W)
        self.tree.column("size",    width=100, stretch=False, anchor=tk.E)
        self.tree.column("ramdisk", width=100, stretch=False, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self._on_double_click)

        self.tree.tag_configure("odd",  background=PANEL_BG)
        self.tree.tag_configure("even", background=DARK_BG)
        self.tree.tag_configure("ram",  foreground=ACCENT)

        # Right-click context menu
        self._ctx_menu = tk.Menu(self.root, tearoff=0, bg=PANEL_BG, fg=TEXT_PRI,
                                 activebackground=HOVER_BG, activeforeground=ACCENT,
                                 bd=0, relief="flat")
        self._ctx_menu.add_command(label="✏️  Rename",        command=self._rename_file)
        self._ctx_menu.add_command(label="➖  Remove",        command=self._remove_file)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="⬇  Extract to RAM", command=self._extract_selected)
        self.tree.bind("<Button-3>", self._show_context_menu)

        # ── per-file action bar (Rename / Remove next to RAM Disk column) ──
        file_action_bar = tk.Frame(self.root, bg=PANEL_BG, pady=4)
        file_action_bar.pack(fill=tk.X, padx=12)

        self._sel_label = tk.Label(file_action_bar, text="No file selected",
                                   bg=PANEL_BG, fg=TEXT_SEC, font=FONT_SMALL)
        self._sel_label.pack(side=tk.LEFT, padx=(6, 12))

        self._btn_rename = self._mk_btn(file_action_bar, "✏️ Rename", self._rename_file)
        self._btn_rename.pack(side=tk.LEFT, padx=3)
        self._btn_remove = self._mk_btn(file_action_bar, "➖ Remove", self._remove_file, danger=True)
        self._btn_remove.pack(side=tk.LEFT, padx=3)

        # Keep action bar label updated on selection change
        self.tree.bind("<<TreeviewSelect>>", self._on_selection_change)

        # ── status bar ─────────────────────────────────────────────────────
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill=tk.X)
        self.status_var = tk.StringVar(value="No container loaded.")
        self.status_lbl = ttk.Label(self.root, textvariable=self.status_var,
                                    style="Status.TLabel")
        self.status_lbl.pack(fill=tk.X)

    def _show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            try:
                self._ctx_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self._ctx_menu.grab_release()

    def _on_selection_change(self, _event=None):
        items = self.tree.selection()
        if items and self.container:
            name = self.tree.item(items[0], "values")[0]
            self._sel_label.config(text=f"Selected: {name}")
            self._btn_rename.config(state="normal")
            self._btn_remove.config(state="normal")
        else:
            self._sel_label.config(text="No file selected")
            self._btn_rename.config(state="disabled")
            self._btn_remove.config(state="disabled")

    # ------------------------------------------------------------------ toggle helpers
    def _get_toggles(self) -> Dict[str, bool]:
        return {
            "kuznyechik":   self._tog_kuz.get(),
            "serpent":      self._tog_serpent.get(),
            "camellia":     True,   # always on
            "scar":         True,   # always on
            "streebog_kdf": self._tog_streebog.get(),
        }

    def _apply_container_toggles(self, toggles: Dict[str, bool]):
        """Push toggles from an opened container back into the GUI checkboxes."""
        self._tog_kuz.set(toggles.get("kuznyechik",   True))
        self._tog_serpent.set(toggles.get("serpent",   True))
        self._tog_streebog.set(toggles.get("streebog_kdf", True))
        self._on_toggle_changed()

    def _on_toggle_changed(self, *_):
        t = self._get_toggles()
        disabled = [k for k in ("kuznyechik", "serpent") if not t[k]]
        if not t["streebog_kdf"]:
            disabled.append("streebog KDF")
        if disabled:
            self._tog_warn.config(
                text="⚠ Reduced security: " + ", ".join(disabled) + " off"
            )
        else:
            self._tog_warn.config(text="")

    def _update_buttons(self):
        if self.state == "empty":
            self._btn_open.config(state="normal")
            self._btn_create.config(state="normal", text="✦  Create")
            self._btn_add.config(state="disabled")
            self._btn_extract.config(state="disabled")
            self._btn_rename.config(state="disabled")
            self._btn_remove.config(state="disabled")
        elif self.state == "creating":
            self._btn_open.config(state="disabled")
            self._btn_create.config(state="normal", text="🔒  Encrypt", command=self._encrypt_container)
            self._btn_add.config(state="disabled")
            self._btn_extract.config(state="disabled")
            self._btn_rename.config(state="disabled")
            self._btn_remove.config(state="disabled")
        elif self.state == "loaded":
            self._btn_open.config(state="normal")
            self._btn_create.config(state="disabled")
            self._btn_add.config(state="normal")
            self._btn_extract.config(state="normal")
            # Rename/Remove stay disabled until a row is selected
            self._btn_rename.config(state="disabled")
            self._btn_remove.config(state="disabled")

    # ------------------------------------------------------------------ helpers
    def _set_status(self, msg: str, warn: bool = False):
        self.status_var.set(msg)
        self.status_lbl.configure(style="Warn.TLabel" if warn else "Status.TLabel")

    def _run_kdf_dialog(self, password: str, toggles: Dict[str, bool]) -> dict:
        """Derive keys once in a background thread and return them."""
        prog = tk.Toplevel(self.root)
        prog.title("Deriving Keys")
        prog.geometry("440x130")
        prog.resizable(False, False)
        prog.configure(bg=DARK_BG)
        prog.transient(self.root)
        prog.grab_set()

        tk.Label(prog, text="Running KDF chains — this may take a moment…",
                 bg=DARK_BG, fg=TEXT_SEC, font=FONT_UI).pack(pady=(18, 4))

        self._kdf_phase = tk.StringVar(value="Initialising…")
        tk.Label(prog, textvariable=self._kdf_phase,
                 bg=DARK_BG, fg=ACCENT, font=FONT_MONO).pack()

        pbar = ttk.Progressbar(prog, style="Accent.Horizontal.TProgressbar",
                               mode="determinate", maximum=1.0, length=380)
        pbar.pack(pady=10)

        result = {}

        _PHASE_LABELS = [
            ("kuznyechik", 0.00), ("serpent", 0.25),
            ("camellia",   0.50), ("scar",    0.75),
        ]

        def cb(fraction):
            label = "Finalising…"
            for name, threshold in reversed(_PHASE_LABELS):
                if fraction >= threshold:
                    label = f"Deriving key material — {name}…"
                    break
            self.root.after(0, lambda f=fraction, l=label: (
                pbar.configure(value=f),
                self._kdf_phase.set(l),
            ))

        def worker():
            try:
                result["keys"] = derive_cipher_keys(password, toggles, cb)
            except Exception as exc:
                result["error"] = str(exc)
            self.root.after(0, prog.destroy)

        threading.Thread(target=worker, daemon=True).start()
        self.root.wait_window(prog)

        if "error" in result:
            raise RuntimeError(result["error"])
        return result["keys"]

    def _ask_password(self, prompt: str, confirm: bool = False) -> Optional[str]:
        dlg = tk.Toplevel(self.root)
        dlg.title("Password")
        dlg.geometry("360x160" if confirm else "360x120")
        dlg.resizable(False, False)
        dlg.configure(bg=DARK_BG)
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(dlg, text=prompt, bg=DARK_BG, fg=TEXT_PRI, font=FONT_UI).pack(pady=(16, 4))
        e1 = tk.Entry(dlg, show="•", bg=PANEL_BG, fg=TEXT_PRI, insertbackground=ACCENT,
                      relief="flat", bd=8, font=FONT_MONO, width=32)
        e1.pack()
        e1.focus_set()

        e2 = None
        if confirm:
            tk.Label(dlg, text="Confirm password:", bg=DARK_BG, fg=TEXT_SEC,
                     font=FONT_UI).pack(pady=(8, 2))
            e2 = tk.Entry(dlg, show="•", bg=PANEL_BG, fg=TEXT_PRI,
                          insertbackground=ACCENT, relief="flat", bd=8,
                          font=FONT_MONO, width=32)
            e2.pack()

        result = {}

        def ok(event=None):
            p = e1.get()
            if not p:
                return
            if confirm and e2 and e2.get() != p:
                tk.Label(dlg, text="Passwords do not match.", bg=DARK_BG,
                         fg=ACCENT2, font=FONT_UI).pack()
                return
            result["pw"] = p
            dlg.destroy()

        def cancel():
            dlg.destroy()

        btn_row = tk.Frame(dlg, bg=DARK_BG)
        btn_row.pack(pady=10)
        self._mk_btn(btn_row, "OK",     ok,     width=10).pack(side=tk.LEFT, padx=6)
        self._mk_btn(btn_row, "Cancel", cancel, danger=True, width=10).pack(side=tk.LEFT, padx=6)

        dlg.bind("<Return>", ok)
        dlg.bind("<Escape>", lambda e: cancel())
        self.root.wait_window(dlg)
        return result.get("pw")

    # ------------------------------------------------------------------ actions
    def _open_container(self):
        path = filedialog.askopenfilename(
            filetypes=[("Encrypted Containers", "*.enc"), ("All Files", "*.*")]
        )
        if not path:
            return
        pwd = self._ask_password("Enter container password:")
        if not pwd:
            return

        try:
            # When opening we don't yet know the toggles — always derive with
            # DEFAULT_TOGGLES (all on) since the header is always fully encrypted.
            keys           = self._run_kdf_dialog(pwd, _DEFAULT_TOGGLES)
            self.container = Container.open(path, keys)
            # Sync GUI checkboxes to what the container was created with
            self._apply_container_toggles(self.container.toggles)
            self.ramdir = self.ramdisk.path
            self.state = "loaded"
            self._update_buttons()
            self._refresh_list()
            self._set_status(f"⊕  Loaded  →  {os.path.basename(path)}  (Version: {self.container.app_version})")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to open container:\n{exc}")

    def _create_container(self):
        out = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted Containers", "*.enc")]
        )
        if not out:
            return
        pwd = self._ask_password("Set container password:", confirm=True)
        if not pwd:
            return

        self.out_path = out          # <-- Store the output path
        self.ramdir = self.ramdisk.path
        self._create_pwd = pwd
        self.state = "creating"
        self._update_buttons()
        self._set_status(f"Created input folder at {self.ramdir}. Copy files here, then click 'Encrypt'.")

    def _encrypt_container(self):
        files_dict = {}
        for fn in os.listdir(self.ramdir):
            fp = os.path.join(self.ramdir, fn)
            if os.path.isfile(fp):
                with open(fp, "rb") as fh:
                    files_dict[fn] = fh.read()

        if not files_dict:
            messagebox.showwarning("Warning", "No files found in the input folder.")
            return

        toggles = self._get_toggles()
        pwd = self._create_pwd

        try:
            def cb(f):
                self._set_status(f"Encrypting…  {f * 100:.1f}%")
                self.root.update_idletasks()
            print("1")
            self.container = Container.create(files_dict, pwd, self.out_path, toggles, progress_cb=cb) # <-- Use self.out_path
            print("2")
            self.state = "loaded"
            self._update_buttons()
            self._set_status(f"✦  Created  →  {os.path.basename(self.out_path)}  (Version: {self.container.app_version})")
            self._refresh_list()
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to create container:\n{exc}")

    def _add_files(self):
        added = 0
        for fn in os.listdir(self.ramdir):
            fp = os.path.join(self.ramdir, fn)
            if os.path.isfile(fp) and fn not in self.container.header["files"]:
                with open(fp, "rb") as fh:
                    data = fh.read()
                self.container.header["files"][fn] = {"offset": 0, "size": len(data), "orig_size": len(data)}
                added += 1
        if added == 0:
            messagebox.showinfo("Info", "No new files found in the RAM disk folder.")
        else:
            self._refresh_list()
            self._set_status(f"Added {added} new files. Click 'Re-encrypt & Save' to apply.")

    def _remove_file(self):
        item = self.tree.selection()
        if not item or not self.container:
            return
        filename = self.tree.item(item[0], "values")[0]
        full_path = os.path.join(self.ramdir, filename)
        if os.path.exists(full_path):
            os.remove(full_path)
        self.container.header["files"].pop(filename, None)
        self._refresh_list()
        self._set_status("Removed file. Click 'Re-encrypt & Save' to apply.")

    def _rename_file(self):
        item = self.tree.selection()
        if not item or not self.container:
            return
        old_name = self.tree.item(item[0], "values")[0]
        new_name = simpledialog.askstring("Rename File", f"New name for {old_name}:")
        if not new_name or new_name == old_name:
            return
        if new_name in self.container.header["files"]:
            messagebox.showerror("Error", f"A file named '{new_name}' already exists.")
            return
        old_path = os.path.join(self.ramdir, old_name)
        new_path = os.path.join(self.ramdir, new_name)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
        if old_name in self.container.header["files"]:
            self.container.header["files"][new_name] = self.container.header["files"].pop(old_name)
        self._refresh_list()
        self._set_status(f"Renamed file to {new_name}. Click 'Re-encrypt & Save' to apply.")

    def _extract_selected(self):
        items = self.tree.selection()
        if not items or not self.container:
            return
        filenames = [self.tree.item(i, "values")[0] for i in items]

        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
            futures = {
                executor.submit(self.container.extract, fn): fn
                for fn in filenames
            }
            for future in as_completed(futures):
                fn = futures[future]
                try:
                    data = future.result()
                    self.ramdisk.write(fn, data)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to extract {fn}:\n{e}")
        self._refresh_list()
        self._set_status(f"Extracted {len(filenames)} files.")

    def _refresh_list(self):
        self.tree.delete(*self.tree.get_children())
        if not self.container:
            return
        ram_files = set(self.ramdisk.list_files())
        for idx, (name, info) in enumerate(self.container.header.get("files", {}).items()):
            size   = _fmt_bytes(info.get("orig_size", info.get("size", 0)))
            in_ram = "✔ RAM" if name in ram_files else "—"
            tags   = ("ram",) if name in ram_files else (("even" if idx % 2 == 0 else "odd"),)
            self.tree.insert("", tk.END, values=(name, size, in_ram), tags=tags)

    def _on_double_click(self, _event):
        item = self.tree.selection()
        if not item or not self.container:
            return
        filename = self.tree.item(item[0], "values")[0]
        full = self.ramdisk.get_full_path(filename)
        if os.path.exists(full):
            if sys.platform.startswith("win"):
                os.startfile(full)
            else:
                import subprocess
                subprocess.call(["xdg-open", full])
        else:
            try:
                plaintext = self.container.extract(filename)
                self.ramdisk.write(filename, plaintext)
                self._refresh_list()
                self._set_status(f"⊕  Extracted to RAM disk  →  {filename}")
                if sys.platform.startswith("win"):
                    os.startfile(self.ramdisk.get_full_path(filename))
                else:
                    import subprocess
                    subprocess.call(["xdg-open", self.ramdisk.get_full_path(filename)])
            except Exception as exc:
                messagebox.showerror("Error", f"Failed to extract file:\n{exc}")

    def _save_container(self):
        if not self.container:
            messagebox.showwarning("Warning", "No container is open.")
            return
        pwd = self._ask_password("Enter password to re-encrypt:")
        if not pwd:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted Containers", "*.enc")]
        )
        if not path:
            return

        toggles = self._get_toggles()

        try:
            files_dict = {}
            for name in self.container.header.get("files", {}).keys():
                fp = os.path.join(self.ramdir, name)
                if os.path.exists(fp):
                    with open(fp, "rb") as fh:
                        files_dict[name] = fh.read()
                else:
                    files_dict[name] = self.container.extract(name)

            def cb(f):
                self._set_status(f"Re-encrypting…  {f * 100:.1f}%")
                self.root.update_idletasks()

            self.container = Container.create(files_dict, pwd, path, toggles, progress_cb=cb)
            self.ramdisk.reset()
            self.ramdir = self.ramdisk.path
            self._refresh_list()
            self._set_status(f"↺  Saved & RAM disk cleared  →  {os.path.basename(path)}  (Version: {self.container.app_version})")
            messagebox.showinfo("Done", "Container re-encrypted and RAM disk cleared.")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to save container:\n{exc}")

    def _clear_ramdisk(self):
        self.ramdisk.reset()
        self.ramdir = self.ramdisk.path
        self._refresh_list()
        self._set_status("⊗  RAM disk cleared.", warn=True)

    def _on_close(self):
        self.ramdisk.clear()
        self.container = None
        self.root.destroy()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    root = tk.Tk()
    ContainerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
        input("Press Enter to exit…")

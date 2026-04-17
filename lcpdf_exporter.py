#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LCPDF Exporter — Decrypt Readium LCP-protected PDF files.
Uses lcpdedrm.py decryption primitives with a lightweight tkinter UI.
"""

import io
import os
import sys
import json
import hashlib
import binascii
import base64
import logging
import re
import tkinter as tk
from tkinter import filedialog, messagebox
from zipfile import ZipFile

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
log = logging.getLogger("lcpdf_to_pdf")
log.setLevel(logging.INFO)


class TextWidgetHandler(logging.Handler):
    """Logging handler that appends to a tkinter Text widget."""

    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record) + "\n"
        # Schedule on the main thread
        self.text_widget.after(0, self._append, msg, record.levelno)

    def _append(self, msg, levelno):
        self.text_widget.configure(state="normal")
        tag = "error" if levelno >= logging.ERROR else "warning" if levelno >= logging.WARNING else "info"
        self.text_widget.insert(tk.END, msg, tag)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state="disabled")

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
try:
    from Crypto.Cipher import AES
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Missing dependency",
        "Required package 'pycryptodome' is not installed.\n\n"
        "Run:  pip install pycryptodome"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# LCP crypto helpers
# ---------------------------------------------------------------------------
import struct
import hmac as _hmac
import zlib

_PROFILE_MASTER_KEY = (
    "b3a07c4d42880e69398e05392405050efeea0664c0b638b7c986556fa9b58d77"
    "b31a40eb6a4fdba1e4537229d9f779daad1cc41ee968153cb71f27dc9696d40f"
)


# ── BLAKE3 (pure-python, from trythis.py) ─────────────────────────────────
_B3_OUT_LEN = 32
_B3_KEY_LEN = 32
_B3_BLOCK_LEN = 64
_B3_CHUNK_LEN = 1024
_B3_CHUNK_START = 1 << 0
_B3_CHUNK_END = 1 << 1
_B3_PARENT = 1 << 2
_B3_ROOT = 1 << 3
_B3_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
          0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
_B3_MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

def _b3_mask32(x): return x & 0xFFFFFFFF
def _b3_add32(x, y): return _b3_mask32(x + y)
def _b3_rotr32(x, n): return _b3_mask32(x << (32 - n)) | (x >> n)

def _b3_g(s, a, b, c, d, mx, my):
    s[a] = _b3_add32(s[a], _b3_add32(s[b], mx))
    s[d] = _b3_rotr32(s[d] ^ s[a], 16)
    s[c] = _b3_add32(s[c], s[d])
    s[b] = _b3_rotr32(s[b] ^ s[c], 12)
    s[a] = _b3_add32(s[a], _b3_add32(s[b], my))
    s[d] = _b3_rotr32(s[d] ^ s[a], 8)
    s[c] = _b3_add32(s[c], s[d])
    s[b] = _b3_rotr32(s[b] ^ s[c], 7)

def _b3_round(s, m):
    _b3_g(s,0,4,8,12,m[0],m[1]); _b3_g(s,1,5,9,13,m[2],m[3])
    _b3_g(s,2,6,10,14,m[4],m[5]); _b3_g(s,3,7,11,15,m[6],m[7])
    _b3_g(s,0,5,10,15,m[8],m[9]); _b3_g(s,1,6,11,12,m[10],m[11])
    _b3_g(s,2,7,8,13,m[12],m[13]); _b3_g(s,3,4,9,14,m[14],m[15])

def _b3_permute(m):
    orig = list(m)
    for i in range(16): m[i] = orig[_B3_MSG_PERM[i]]

def _b3_compress(cv, bw, counter, bl, flags):
    s = [cv[0],cv[1],cv[2],cv[3],cv[4],cv[5],cv[6],cv[7],
         _B3_IV[0],_B3_IV[1],_B3_IV[2],_B3_IV[3],
         _b3_mask32(counter),_b3_mask32(counter>>32),bl,flags]
    block = list(bw)
    for _ in range(7): _b3_round(s, block); _b3_permute(block)
    for i in range(8): s[i] ^= s[i+8]; s[i+8] ^= cv[i]
    return s

def _b3_words(b):
    return [int.from_bytes(b[i:i+4], "little") for i in range(0, len(b), 4)]

class _B3Output:
    def __init__(self, icv, bw, ctr, bl, fl):
        self.icv, self.bw, self.ctr, self.bl, self.fl = icv, bw, ctr, bl, fl
    def cv(self):
        return _b3_compress(self.icv, self.bw, self.ctr, self.bl, self.fl)[:8]
    def root_bytes(self, length):
        out = bytearray(); i = 0
        while i < length:
            words = _b3_compress(self.icv, self.bw, i//64, self.bl, self.fl | _B3_ROOT)
            for w in words:
                wb = w.to_bytes(4, "little"); take = min(len(wb), length - i)
                out.extend(wb[:take]); i += take
        return bytes(out)

class _B3Chunk:
    def __init__(self, kw, cc, fl):
        self.cv, self.cc, self.block = list(kw), cc, bytearray(_B3_BLOCK_LEN)
        self.blen, self.bcomp, self.fl = 0, 0, fl
    def total(self): return _B3_BLOCK_LEN * self.bcomp + self.blen
    def sflag(self): return _B3_CHUNK_START if self.bcomp == 0 else 0
    def update(self, data):
        while data:
            if self.blen == _B3_BLOCK_LEN:
                self.cv = _b3_compress(self.cv, _b3_words(self.block), self.cc, _B3_BLOCK_LEN, self.fl | self.sflag())[:8]
                self.bcomp += 1; self.block = bytearray(_B3_BLOCK_LEN); self.blen = 0
            take = min(_B3_BLOCK_LEN - self.blen, len(data))
            self.block[self.blen:self.blen+take] = data[:take]; self.blen += take; data = data[take:]
    def output(self):
        return _B3Output(self.cv, _b3_words(self.block), self.cc, self.blen, self.fl | self.sflag() | _B3_CHUNK_END)

def _blake3(data, length=32):
    kw = list(_B3_IV); stack = []; cs = _B3Chunk(kw, 0, 0)
    pos = 0
    while pos < len(data):
        if cs.total() == _B3_CHUNK_LEN:
            ccv = cs.output().cv(); tc = cs.cc + 1
            while tc & 1 == 0: ccv = _b3_compress(stack.pop(), ccv + [0]*8, 0, _B3_BLOCK_LEN, _B3_PARENT)[:8]; tc >>= 1
            stack.append(ccv); cs = _B3Chunk(kw, tc, 0)
        take = min(_B3_CHUNK_LEN - cs.total(), len(data) - pos)
        cs.update(data[pos:pos+take]); pos += take
    out = cs.output()
    for i in range(len(stack)-1, -1, -1):
        parent_bw = stack[i] + out.cv()
        out = _B3Output(kw, parent_bw, 0, _B3_BLOCK_LEN, _B3_PARENT)
    return out.root_bytes(length)


# ── Hash/crypto primitives ────────────────────────────────────────────────
def _crc32bts(data):
    return struct.pack('>I', zlib.crc32(data) & 0xFFFFFFFF)

def _adler32bts(data):
    return struct.pack('>I', zlib.adler32(data) & 0xFFFFFFFF)

def _hmac256(key, msg):
    return _hmac.new(key, msg, hashlib.sha256).digest()

def _hmacmd5(key, msg):
    return _hmac.new(key, msg, hashlib.md5).digest()

def _pbkdf2_sha256(msg, salt, iters):
    return hashlib.pbkdf2_hmac('sha256', msg, salt, iters, dklen=32)

def _pbkdf2_md5(msg, salt, iters):
    return hashlib.pbkdf2_hmac('md5', msg, salt, iters, dklen=16)

def _pbkdf2_sha1(msg, salt, iters):
    return hashlib.pbkdf2_hmac('sha1', msg, salt, iters, dklen=20)

def _md5(data):
    return hashlib.md5(data).digest()

def _fnv11_interleaved(data):
    P, B = 0x01000193, 0x811c9dc5
    h, hi = B, B
    for byte in data:
        hi = ((hi * P) & 0xFFFFFFFF) ^ byte
        h = ((h ^ byte) * P) & 0xFFFFFFFF
    return bytes([(h>>24)&0xff,(hi>>24)&0xff,(h>>16)&0xff,(hi>>16)&0xff,
                  (h>>8)&0xff,(hi>>8)&0xff,h&0xff,hi&0xff])

def _xorstrs(s1, s2):
    return bytes(s1[i % len(s1)] ^ s2[i] for i in range(len(s2)))

def _getindex(bts, md):
    offs = bts[0] % len(bts)
    if offs == 0: return 1
    ret = bts[offs - 1] % md
    return ret if ret != 0 else 1

def _sha256hex(data):
    return binascii.hexlify(hashlib.sha256(data).digest()).decode("latin-1")


# ── Profile transforms ────────────────────────────────────────────────────
def _identity_transform(input_hash):
    return input_hash

def _transform_profile10(input_hash):
    masterkey = bytearray.fromhex(_PROFILE_MASTER_KEY)
    try:
        current_hash = bytearray.fromhex(input_hash)
    except (ValueError, TypeError):
        return None
    for byte in masterkey:
        current_hash.append(byte)
        current_hash = bytearray(hashlib.sha256(current_hash).digest())
    return binascii.hexlify(current_hash).decode("latin-1")

def _transform_profile20(input_hash):
    try: mk = bytearray.fromhex(input_hash)
    except: return None
    blk = _blake3(mk, 64)
    crc = _crc32bts(blk); adlr = _adler32bts(blk)
    h = _hmac256(adlr, blk + crc + adlr)
    return _sha256hex(h)

def _transform_profile21(input_hash):
    try: mk = bytearray.fromhex(input_hash)
    except: return None
    blk = _blake3(mk, 32)
    crc = _crc32bts(blk); adlr = _adler32bts(blk)
    iters = _getindex(mk, 9)
    h = _pbkdf2_sha256(crc + adlr + blk + crc + adlr, crc, iters)
    return _sha256hex(h)

def _transform_profile22(input_hash):
    try: mk = bytearray.fromhex(input_hash)
    except: return None
    hsh = hashlib.sha256(mk).digest()
    crc = _crc32bts(hsh); adlr = _adler32bts(hsh)
    iters = _getindex(mk, 9)
    h = _pbkdf2_md5(crc + adlr + hsh + crc + adlr, adlr, iters)
    return _sha256hex(h)

def _transform_profile23(input_hash):
    try: mk = bytearray.fromhex(input_hash)
    except: return None
    blk1 = _blake3(mk, 64); blk2 = _blake3(blk1, 32)
    adlr = _adler32bts(mk)
    iters = _getindex(adlr, 10)
    h = _pbkdf2_sha1(blk1 + blk2, adlr, iters)
    return _sha256hex(h)

def _transform_profile24(input_hash):
    try: mk = bytearray.fromhex(input_hash)
    except: return None
    ostr = bytes.fromhex("496e76616c696420626c6f636b2073697a65213f")
    st1 = _xorstrs(mk, ostr); st2 = hashlib.sha256(mk).digest()
    h = _hmac256(st1, st2); blk = _blake3(h, 32)
    adlr = _adler32bts(mk); iters = _getindex(mk, 9)
    h = _pbkdf2_sha1(blk, adlr, iters)
    return _sha256hex(h)

def _transform_profile25(input_hash):
    try: mk = bytearray.fromhex(input_hash)
    except: return None
    fnv = _fnv11_interleaved(mk); st1 = _xorstrs(fnv, mk)
    st2 = hashlib.sha256(mk).digest(); h = _hmac256(st1, st2)
    blk = _blake3(h + fnv + h + st1, 32)
    adlr = _adler32bts(mk); iters = _getindex(mk, 9)
    h = _pbkdf2_md5(blk, adlr, iters)
    return _sha256hex(h)

def _transform_profile26(input_hash):
    try: mk = bytearray.fromhex(input_hash)
    except: return None
    fnv = _fnv11_interleaved(mk); st1 = _xorstrs(fnv, mk)
    blk1 = _blake3(mk, 64); h = _hmac256(st1 + st1, blk1)
    blk = _blake3(h, 32)
    return _sha256hex(blk)

def _transform_profile27(input_hash):
    try: mk = bytearray.fromhex(input_hash)
    except: return None
    fnv = _fnv11_interleaved(mk); st1 = _xorstrs(fnv, mk)
    adl5 = _adler32bts(st1); crc6 = _crc32bts(st1)
    blk1 = _blake3(st1 + st1 + fnv + st1 + fnv + crc6 + adl5, 32)
    h = _hmacmd5(st1 + st1, blk1) + b"\x00\x00\x00\x00"
    blk2 = _blake3(h, 64)
    return _sha256hex(blk2)

def _transform_profile28(input_hash):
    try: mk = bytearray.fromhex(input_hash)
    except: return None
    _1 = _fnv11_interleaved(mk); _2 = _xorstrs(_1, mk)
    _4 = _adler32bts(_2); _5 = _crc32bts(_2)
    _6 = _pbkdf2_sha1(_2 + _2, _1 + _5 + _4, 3)
    _7 = _hmac256(_2, _6); _8 = _blake3(_7, 32)
    _9 = _adler32bts(mk); it = _getindex(_9, 9)
    _11 = _pbkdf2_sha1(_8, _9, it)
    return _sha256hex(_11)

def _transform_profile29(input_hash):
    try: mk = bytearray.fromhex(input_hash)
    except: return None
    _1 = _blake3(mk, 32); _2 = _md5(mk)
    _3 = _fnv11_interleaved(_1)
    _5 = _adler32bts(_2); _6 = _crc32bts(_2)
    _7 = _3 + _3 + _1 + _3 + _3
    it = _getindex(mk, 9)
    _9 = _pbkdf2_sha256(_7, _5 + _6, it)
    return _sha256hex(_9)


def userpass_to_hash(passphrase_bytes, algorithm):
    """Hash a passphrase according to the LCP user-key algorithm."""
    if algorithm == "http://www.w3.org/2001/04/xmlenc#sha256":
        return hashlib.sha256(passphrase_bytes).hexdigest()
    return None


def decrypt_lcp_data(b64data, hex_key):
    """Decrypt a base64-encoded LCP value with an AES key (hex string)."""
    raw = base64.b64decode(b64data.encode("ascii"))
    iv, cipher = raw[:16], raw[16:]
    aes = AES.new(binascii.unhexlify(hex_key), AES.MODE_CBC, iv)
    temp = aes.decrypt(cipher)
    pad = temp[-1] if isinstance(temp[-1], int) else ord(temp[-1])
    return temp[:-pad]


# ---------------------------------------------------------------------------
# Known LCP profiles
# ---------------------------------------------------------------------------
KNOWN_PROFILES = {
    "http://readium.org/lcp/basic-profile": _identity_transform,
    "http://readium.org/lcp/profile-1.0": _transform_profile10,
    "http://readium.org/lcp/profile-2.0": _transform_profile20,
    "http://readium.org/lcp/profile-2.1": _transform_profile21,
    "http://readium.org/lcp/profile-2.2": _transform_profile22,
    "http://readium.org/lcp/profile-2.3": _transform_profile23,
    "http://readium.org/lcp/profile-2.4": _transform_profile24,
    "http://readium.org/lcp/profile-2.5": _transform_profile25,
    "http://readium.org/lcp/profile-2.6": _transform_profile26,
    "http://readium.org/lcp/profile-2.7": _transform_profile27,
    "http://readium.org/lcp/profile-2.8": _transform_profile28,
    "http://readium.org/lcp/profile-2.9": _transform_profile29,
}

# Profiles where we are confident the transform is correct
VERIFIED_PROFILES = set(KNOWN_PROFILES.keys())


# ---------------------------------------------------------------------------
# Thorium Reader passphrase extraction
# ---------------------------------------------------------------------------
_THORIUM_SECRET_RE = re.compile(
    rb'"(?:secret|passPhrase|passphrase|pass_phrase|lcpHashedPassphrase'
    rb'|hashedPassphrase|userPassPhrase)"\s*:\s*"([^"]{1,256})"'
)


def _try_find_thorium_passphrase(book_id):
    """
    Scan Thorium Reader's local storage for a cached passphrase associated
    with the given LCP license/book ID.
    Returns the passphrase (or passphrase hash) string if found, None otherwise.
    Designed to fail completely silently.
    """
    if not book_id:
        return None

    # Build list of candidate Thorium data directories (platform-aware)
    dirs = []
    for var in ("APPDATA", "LOCALAPPDATA"):
        base = os.environ.get(var, "")
        if base:
            dirs.append(os.path.join(base, "EDRLab", "Thorium"))
            dirs.append(os.path.join(base, "Thorium"))
    home = os.path.expanduser("~")
    if sys.platform == "darwin":
        dirs.append(os.path.join(home, "Library", "Application Support", "EDRLab.Thorium"))
    elif sys.platform.startswith("linux"):
        dirs.append(os.path.join(home, ".config", "EDRLab", "Thorium"))
        dirs.append(os.path.join(home, ".config", "thorium"))

    needle = book_id.encode("utf-8")
    files_checked = 0
    max_files = 2000
    dirs_found = [d for d in dirs if os.path.isdir(d)]

    if not dirs_found:
        log.info("Thorium Reader not found on this system")
        return None

    log.info("Scanning Thorium storage for cached passphrase...")

    for base_dir in dirs_found:
        try:
            for dirpath, _dirnames, filenames in os.walk(base_dir):
                for fname in filenames:
                    if files_checked >= max_files:
                        break
                    fpath = os.path.join(dirpath, fname)
                    try:
                        fsize = os.path.getsize(fpath)
                        if fsize == 0 or fsize > 20 * 1024 * 1024:
                            continue
                        files_checked += 1
                        with open(fpath, "rb") as fh:
                            data = fh.read()
                        if needle not in data:
                            continue
                        # File contains the book ID — look for passphrase fields
                        log.info("Book ID found in: %s", fname)
                        for m in _THORIUM_SECRET_RE.finditer(data):
                            value = m.group(1).decode("utf-8", errors="ignore").strip()
                            if value:
                                return value
                    except Exception:
                        continue
                if files_checked >= max_files:
                    break
        except Exception:
            continue

    log.info("No cached passphrase found in Thorium (%d files checked)", files_checked)
    return None


# ---------------------------------------------------------------------------
# File info extraction
# ---------------------------------------------------------------------------
def peek_lcpdf_info(filepath):
    """
    Read metadata from an LCPDF zip without decrypting.
    Returns dict with keys: title, profile, profile_short, cover_bytes (or None for each).
    """
    info = {"title": None, "profile": None, "profile_short": None, "cover_bytes": None, "book_id": None}
    try:
        zf = ZipFile(open(filepath, "rb"))
    except Exception:
        return info

    # License → profile
    for candidate in ("license.lcpl", "META-INF/license.lcpl"):
        if candidate in zf.namelist():
            try:
                lic = json.loads(zf.read(candidate))
                info["profile"] = lic.get("encryption", {}).get("profile", None)
                if info["profile"]:
                    info["profile_short"] = info["profile"].split("/")[-1]
                info["book_id"] = lic.get("id")
            except Exception:
                pass
            break

    # Manifest → title + cover path
    if "manifest.json" in zf.namelist():
        try:
            manifest = json.loads(zf.read("manifest.json"))
            info["title"] = manifest.get("metadata", {}).get("title", None)
            for res in manifest.get("resources", []):
                if "cover" in str(res.get("rel", "")):
                    cover_href = res.get("href")
                    if cover_href and cover_href in zf.namelist():
                        info["cover_bytes"] = zf.read(cover_href)
                    break
        except Exception:
            pass

    # Fallback: look for common cover filenames
    if info["cover_bytes"] is None:
        for name in zf.namelist():
            if "cover" in name.lower() and name.lower().endswith((".jpg", ".jpeg", ".png")):
                try:
                    info["cover_bytes"] = zf.read(name)
                except Exception:
                    pass
                break

    zf.close()
    return info


# ---------------------------------------------------------------------------
# Core decryption
# ---------------------------------------------------------------------------
def find_license_in_zip(zf):
    """Locate license.lcpl inside a ZIP (LCPDF or EPUB-LCP layout)."""
    for candidate in ("license.lcpl", "META-INF/license.lcpl"):
        if candidate in zf.namelist():
            return candidate
    return None


def find_pdf_in_zip(zf):
    """Return list of .pdf file paths inside the ZIP."""
    return [n for n in zf.namelist() if n.lower().endswith(".pdf")]


def decrypt_lcpdf(filepath, passphrase):
    """
    Decrypt an LCPDF file.

    Returns (output_path, None) on success, or (None, error_message) on failure.
    """
    log.info("Opening file: %s", filepath)

    # ── Open ZIP ──────────────────────────────────────────────────────────
    try:
        zf = ZipFile(open(filepath, "rb"))
    except Exception as e:
        log.error("Failed to open as ZIP: %s", e)
        return None, f"The selected file could not be read as a valid LCPDF package.\n\nDetails: {e}"

    # ── Locate license ────────────────────────────────────────────────────
    license_path = find_license_in_zip(zf)
    if license_path is None:
        log.error("No license.lcpl found in ZIP")
        zf.close()
        return None, "No license.lcpl found in the LCPDF package."

    log.info("Found license at: %s", license_path)

    try:
        license_data = json.loads(zf.read(license_path))
    except Exception as e:
        zf.close()
        return None, f"license.lcpl could not be parsed as JSON.\n\nDetails: {e}"

    # ── Validate required license fields ──────────────────────────────────
    try:
        book_id = license_data["id"]
        profile = license_data["encryption"]["profile"]
        encrypted_content_key = license_data["encryption"]["content_key"]["encrypted_value"]
        key_check = license_data["encryption"]["user_key"]["key_check"]
        user_key_algo = license_data["encryption"]["user_key"].get(
            "algorithm", "http://www.w3.org/2001/04/xmlenc#sha256"
        )
    except KeyError as e:
        zf.close()
        return None, f"license.lcpl is missing a required field: {e}"

    log.info("Book ID: %s", book_id)
    log.info("Encryption profile: %s", profile)
    log.info("User key algorithm: %s", user_key_algo)

    # ── Locate encrypted PDF(s) ───────────────────────────────────────────
    pdf_files = find_pdf_in_zip(zf)
    if not pdf_files:
        zf.close()
        return None, "No PDF file found inside the LCPDF package."

    log.info("Found %d PDF file(s) in package: %s", len(pdf_files), ", ".join(pdf_files))

    # ── Check profile ─────────────────────────────────────────────────────
    profile_known = profile in KNOWN_PROFILES
    profile_short = profile.split("/")[-1] if "/" in profile else profile

    if profile_known:
        log.info("Profile '%s' is supported", profile_short)
    else:
        log.warning("Profile '%s' is NOT officially supported — will try best-effort transforms", profile_short)

    # ── Build list of password hashes to try ──────────────────────────────
    password_hashes = []

    # Some providers embed the key directly in the license
    user_key_section = license_data["encryption"]["user_key"]
    if "value" in user_key_section:
        try:
            password_hashes.append(
                binascii.hexlify(base64.b64decode(user_key_section["value"])).decode("ascii")
            )
        except Exception:
            pass
    if "hex_value" in user_key_section:
        try:
            password_hashes.append(
                binascii.hexlify(bytearray.fromhex(user_key_section["hex_value"])).decode("ascii")
            )
        except Exception:
            pass

    # Hash the user-provided passphrase
    hashed_pw = userpass_to_hash(passphrase.encode("utf-8"), user_key_algo)
    if hashed_pw is not None:
        password_hashes.append(hashed_pw)
    # Also try the raw passphrase as a hex string (edge case)
    password_hashes.append(passphrase)

    log.info("Prepared %d password hash candidates", len(password_hashes))

    # ── Try each hash with each transform ─────────────────────────────────
    # Build transform list: always try basic (identity). Add known profile
    # transform, plus profile-1.0 as a fallback.
    transforms = [("basic (identity)", _identity_transform)]
    if profile_known:
        transforms.insert(0, (profile_short, KNOWN_PROFILES[profile]))
    if not profile_known:
        # Try all known 2.x transforms as best-effort for unknown profiles
        for url, fn in KNOWN_PROFILES.items():
            name = url.split("/")[-1]
            if (name, fn) not in [(t[0], t[1]) for t in transforms]:
                transforms.append((name + " (fallback)", fn))

    log.info("Trying %d transform(s): %s", len(transforms), ", ".join(t[0] for t in transforms))

    correct_hash = None
    for pw_hash in password_hashes:
        for _tname, transform_fn in transforms:
            try:
                transformed = transform_fn(pw_hash)
            except Exception:
                continue
            if transformed is None:
                continue
            try:
                decrypted_check = decrypt_lcp_data(key_check, transformed)
            except Exception:
                continue
            if decrypted_check is not None and decrypted_check.decode("ascii", errors="ignore") == book_id:
                correct_hash = transformed
                break
        if correct_hash is not None:
            break

    if correct_hash is None:
        log.error("No matching passphrase found after trying all candidates and transforms")
        hint = user_key_section.get("text_hint", "")
        if profile not in VERIFIED_PROFILES:
            msg = (
                f"Decryption failed.\n\n"
                f"This file uses LCP encryption profile '{profile_short}' "
                f"which is not recognized.\n\n"
                f"The passphrase may also be incorrect."
            )
        else:
            msg = "Decryption failed: the passphrase is incorrect."
        if hint:
            msg += f"\n\nHint from distributor: \"{hint}\""
        # Add link hint if available
        for link in license_data.get("links", []):
            if link.get("rel") == "hint":
                msg += f"\n\nYou may find or reset your passphrase at:\n{link['href']}"
                break
        zf.close()
        return None, msg

    log.info("Passphrase verified successfully — decrypting content key")

    # ── Decrypt the content key ───────────────────────────────────────────
    try:
        content_key = decrypt_lcp_data(encrypted_content_key, correct_hash)
    except Exception as e:
        zf.close()
        return None, f"Failed to decrypt the content key.\n\nDetails: {e}"

    if content_key is None:
        zf.close()
        return None, "Decrypted content key is empty."

    log.info("Content key decrypted (%d bytes)", len(content_key))

    # ── Decrypt the PDF ───────────────────────────────────────────────────
    pdf_name = pdf_files[0]
    log.info("Decrypting PDF: %s", pdf_name)
    try:
        encrypted_pdf = zf.read(pdf_name)
    except Exception as e:
        zf.close()
        return None, f"Could not read '{pdf_name}' from the package.\n\nDetails: {e}"

    zf.close()

    log.info("Encrypted PDF size: %.2f MB", len(encrypted_pdf) / (1024 * 1024))

    if len(encrypted_pdf) < 17:
        return None, f"Encrypted PDF '{pdf_name}' is too small to contain valid data."

    iv = encrypted_pdf[:16]
    ciphertext = encrypted_pdf[16:]

    try:
        aes = AES.new(content_key, AES.MODE_CBC, iv)
        decrypted_pdf = aes.decrypt(ciphertext)
    except Exception as e:
        return None, f"AES decryption of PDF failed.\n\nDetails: {e}"

    # Remove PKCS7 padding
    pad_len = decrypted_pdf[-1] if isinstance(decrypted_pdf[-1], int) else ord(decrypted_pdf[-1])
    if 1 <= pad_len <= 16:
        decrypted_pdf = decrypted_pdf[:-pad_len]

    log.info("Decrypted PDF size: %.2f MB", len(decrypted_pdf) / (1024 * 1024))

    # Quick sanity: PDF should start with %PDF
    if not decrypted_pdf[:5].startswith(b"%PDF"):
        return None, (
            "Decryption completed but the result does not appear to be a valid PDF.\n\n"
            "This may indicate the passphrase was accepted by key_check but "
            "the content key derivation differs for this profile."
        )

    # ── Write output ──────────────────────────────────────────────────────
    base = os.path.splitext(os.path.basename(filepath))[0]
    # Strip extra .lcpdf if present (e.g. "book.lcpdf.zip" → "book")
    if base.lower().endswith(".lcpdf"):
        base = base[:-6]
    output_path = os.path.join(os.path.dirname(filepath), base + ".pdf")

    log.info("Writing output to: %s", output_path)

    try:
        with open(output_path, "wb") as f:
            f.write(decrypted_pdf)
    except Exception as e:
        log.error("Failed to write output: %s", e)
        return None, f"Could not write output file.\n\nDetails: {e}"

    log.info("Done — decrypted PDF saved successfully")
    return output_path, None


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
_BG = "#0d1117"
_BG2 = "#161b22"
_FG = "#c9d1d9"
_GREEN = "#3fb950"
_RED = "#f85149"
_YELLOW = "#d29922"
_ACCENT = "#58a6ff"
_DIM = "#6e7681"
_FONT = ("Consolas", 10)
_FONT_SM = ("Consolas", 9)
_FONT_LG = ("Consolas", 14, "bold")
_FONT_TITLE = ("Consolas", 11, "bold")


def main():
    root = tk.Tk()
    root.title("LCPDF to PDF Exporter")
    root.configure(bg=_BG)
    root.resizable(True, True)
    root.minsize(680, 560)

    # Window icon (green open-lock, drawn with PIL)
    try:
        if HAS_PIL:
            from PIL import ImageDraw
            _sz = 48
            _ico = Image.new("RGBA", (_sz, _sz), (0, 0, 0, 0))
            _d = ImageDraw.Draw(_ico)
            _green = (0x3f, 0xb9, 0x50, 255)
            _dark = (0x0d, 0x11, 0x17, 255)
            # Body (rounded rectangle, lower portion)
            _d.rounded_rectangle([6, 22, 36, 44], radius=3, fill=_green)
            # Shackle (open — shifted right, only left side attached)
            # Left arm of shackle
            _d.rectangle([11, 8, 15, 24], fill=_green)
            # Top arc connecting left to right
            _d.arc([11, 2, 35, 22], 180, 360, fill=_green, width=5)
            # Right arm — raised up to show "open"
            _d.rectangle([31, 2, 35, 14], fill=_green)
            # Keyhole
            _d.ellipse([18, 29, 24, 35], fill=_dark)
            _d.polygon([(19, 34), (23, 34), (22, 40), (20, 40)], fill=_dark)
            _icon_photo = ImageTk.PhotoImage(_ico)
            root.iconphoto(True, _icon_photo)
            root._icon_ref = _icon_photo  # prevent GC
    except Exception:
        pass

    # ── Header ────────────────────────────────────────────────────────────
    hdr = tk.Frame(root, bg=_BG)
    hdr.pack(fill=tk.X, padx=16, pady=(14, 2))

    tk.Label(hdr, text="\U0001F513 LCPDF to PDF", font=_FONT_LG, bg=_BG, fg=_GREEN).pack(side=tk.LEFT)
    tk.Label(hdr, text="// export LCP-protected file to PDF", font=_FONT_SM, bg=_BG, fg=_DIM).pack(side=tk.LEFT, padx=(10, 0))

    # ── Separator ─────────────────────────────────────────────────────────
    tk.Frame(root, bg=_DIM, height=1).pack(fill=tk.X, padx=16, pady=(6, 10))

    # ── Top area: left (controls) + right (cover) ─────────────────────────
    top = tk.Frame(root, bg=_BG)
    top.pack(fill=tk.X, padx=16, pady=(0, 6))

    left = tk.Frame(top, bg=_BG)
    left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Cover on the right
    cover_frame = tk.Frame(top, bg=_BG2, width=180, height=240, relief="flat",
                           highlightbackground=_DIM, highlightthickness=1)
    cover_frame.pack(side=tk.RIGHT, padx=(14, 0), anchor="n")
    cover_frame.pack_propagate(False)

    cover_label = tk.Label(cover_frame, text="[ no cover ]", font=_FONT_SM,
                           bg=_BG2, fg=_DIM, anchor="center")
    cover_label.pack(expand=True)
    cover_label._photo_ref = None

    # ── File row ──────────────────────────────────────────────────────────
    tk.Label(left, text="TARGET FILE  (.lcpdf / .lcpdf.zip)", font=_FONT_SM,
             bg=_BG, fg=_DIM, anchor="w").pack(fill=tk.X)

    file_row = tk.Frame(left, bg=_BG)
    file_row.pack(fill=tk.X, pady=(2, 8))

    file_var = tk.StringVar()
    file_entry = tk.Entry(file_row, textvariable=file_var, state="readonly",
                          font=_FONT, bg=_BG2, fg=_FG, insertbackground=_FG,
                          readonlybackground=_BG2, disabledforeground=_FG,
                          relief="flat", highlightbackground=_DIM, highlightthickness=1)
    file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)

    def browse_file():
        path = filedialog.askopenfilename(
            title="Select an LCPDF file (.lcpdf or .lcpdf.zip)",
            filetypes=[
                ("LCPDF files", "*.lcpdf *.lcpdf.zip"),
                ("ZIP files", "*.zip"),
                ("All files", "*.*"),
            ],
        )
        if path:
            file_var.set(path)
            log.info("Target acquired: %s", path)
            _update_file_info(path)

    browse_btn = tk.Button(file_row, text=" Browse ", font=_FONT_SM,
                           bg=_BG2, fg=_ACCENT, activebackground=_BG,
                           activeforeground=_GREEN, relief="flat", cursor="hand2",
                           highlightbackground=_DIM, highlightthickness=1,
                           command=browse_file)
    browse_btn.pack(side=tk.LEFT, padx=(6, 0), ipady=2)

    # ── File info labels ──────────────────────────────────────────────────
    title_var = tk.StringVar(value="")
    title_label = tk.Label(left, textvariable=title_var, font=_FONT_TITLE,
                           bg=_BG, fg=_FG, anchor="w")
    title_label.pack(fill=tk.X)

    profile_var = tk.StringVar(value="")
    profile_label = tk.Label(left, textvariable=profile_var, font=_FONT_SM,
                             bg=_BG, fg=_DIM, anchor="w")
    profile_label.pack(fill=tk.X, pady=(0, 8))

    def _update_file_info(path):
        title_var.set("")
        profile_var.set("")
        cover_label.configure(image="", text="[ no cover ]")
        cover_label._photo_ref = None

        info = peek_lcpdf_info(path)

        if info["title"]:
            title_var.set(f"» {info['title']}")
            log.info("Title: %s", info["title"])

        if info["profile_short"]:
            supported = info["profile"] in KNOWN_PROFILES
            status = "SUPPORTED ✓" if supported else "UNKNOWN ✗"
            profile_var.set(f"LCP {info['profile_short']}  —  {status}")
            profile_label.configure(fg=_GREEN if supported else _RED)
            log.info("Profile: %s (%s)", info["profile_short"], status)

        if info["cover_bytes"] and HAS_PIL:
            try:
                img = Image.open(io.BytesIO(info["cover_bytes"]))
                img.thumbnail((176, 236))
                photo = ImageTk.PhotoImage(img)
                cover_label.configure(image=photo, text="")
                cover_label._photo_ref = photo
                log.info("Cover loaded")
            except Exception:
                pass
        elif info["cover_bytes"] and not HAS_PIL:
            log.info("Cover found but Pillow not installed (pip install Pillow)")

        # Try to auto-fill passphrase from Thorium Reader
        if info.get("book_id"):
            try:
                cached_pw = _try_find_thorium_passphrase(info["book_id"])
                if cached_pw:
                    pass_var.set(cached_pw)
                    log.info("Passphrase auto-filled from Thorium Reader")
            except Exception:
                pass

    # ── Passphrase row ────────────────────────────────────────────────────
    tk.Label(left, text="PASSPHRASE", font=_FONT_SM, bg=_BG, fg=_DIM,
             anchor="w").pack(fill=tk.X)

    pass_row = tk.Frame(left, bg=_BG)
    pass_row.pack(fill=tk.X, pady=(2, 10))

    pass_var = tk.StringVar()
    pass_entry = tk.Entry(pass_row, textvariable=pass_var, show="●", font=_FONT,
                          bg=_BG2, fg=_FG, insertbackground=_FG, relief="flat",
                          highlightbackground=_DIM, highlightthickness=1)
    pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)

    # ── Export button ─────────────────────────────────────────────────────
    def run_decrypt(event=None):
        filepath = file_var.get().strip()
        passphrase = pass_var.get()

        if not filepath:
            log.error("No file selected — browse for an LCPDF file first")
            return
        if not passphrase:
            log.error("No passphrase entered")
            return

        export_btn.configure(state="disabled", text="⏳ Exporting...")
        root.update_idletasks()

        log.info("Starting export...")
        output_path, error = decrypt_lcpdf(filepath, passphrase)

        if error:
            log.error(error.replace("\n", " | "))
            export_btn.configure(text="✗ FAILED", fg=_RED)
            messagebox.showerror("Export Failed", error, parent=root)
            export_btn.configure(text="🔓 Export as PDF", fg=_BG, state="normal")
        else:
            log.info("Exported to: %s", output_path)
            export_btn.configure(text="✓ Done!", fg=_BG)
            messagebox.showinfo("Export Complete", f"PDF saved to:\n\n{output_path}", parent=root)
            export_btn.configure(text="🔓 Export as PDF", fg=_BG, state="normal")

    export_btn = tk.Button(left, text="🔓 Export as PDF", font=("Consolas", 12, "bold"),
                           bg=_GREEN, fg=_BG, activebackground=_ACCENT,
                           activeforeground=_BG, relief="flat", cursor="hand2",
                           command=run_decrypt, height=1)
    export_btn.pack(fill=tk.X, ipady=4)

    # Enter key binding
    root.bind("<Return>", run_decrypt)

    # ── Log area ──────────────────────────────────────────────────────────
    tk.Frame(root, bg=_DIM, height=1).pack(fill=tk.X, padx=16, pady=(10, 0))

    tk.Label(root, text="TERMINAL", font=_FONT_SM, bg=_BG, fg=_DIM,
             anchor="w").pack(fill=tk.X, padx=16, pady=(6, 0))

    log_frame = tk.Frame(root, bg=_BG)
    log_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(2, 12))

    log_text = tk.Text(log_frame, height=10, state="disabled", wrap=tk.WORD,
                       bg=_BG2, fg=_FG, font=_FONT_SM, relief="flat",
                       highlightbackground=_DIM, highlightthickness=1,
                       padx=8, pady=6)
    log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(log_frame, command=log_text.yview,
                             bg=_BG2, troughcolor=_BG, activebackground=_DIM)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    log_text.configure(yscrollcommand=scrollbar.set)

    # Tag colours
    log_text.tag_configure("info", foreground=_FG)
    log_text.tag_configure("warning", foreground=_YELLOW)
    log_text.tag_configure("error", foreground=_RED)

    # Wire up the logging handler
    handler = TextWidgetHandler(log_text)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    log.addHandler(handler)

    log.info("LCPDF to PDF exporter initialized — profiles 1.0 through 2.9 loaded")
    log.info("Select a file and enter the passphrase, then hit Export as PDF (or Enter)")

    root.mainloop()


if __name__ == "__main__":
    main()

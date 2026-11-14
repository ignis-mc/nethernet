"""AES in ECB mode with PKCS#7 padding.

ECB encrypts equal plaintext blocks to equal ciphertext blocks and provides no
integrity. It exists here only because the NetherNet LAN discovery packet
format uses AES-256-ECB; that format authenticates the plaintext with a
separate HMAC. Do not use it for anything else.

Block operations run on `Aes`, which is constant-time. The padding check does
not branch on or index by plaintext bytes; whether it succeeded, and the
unpadded length, are necessarily visible to the caller.
"""

from .aes import AES_BLOCK_LEN, Aes


def _ecb_encrypt_with(
    aes: Aes, plaintext: Span[UInt8, _], mut out: List[UInt8]
):
    var n = len(plaintext)
    var pad = AES_BLOCK_LEN - n % AES_BLOCK_LEN
    var total = n + pad
    out.reserve(len(out) + total)
    var block = Array[UInt8, 16](fill=0)
    for off in range(0, total, AES_BLOCK_LEN):
        for i in range(AES_BLOCK_LEN):
            if off + i < n:
                block[i] = plaintext[off + i]
            else:
                block[i] = UInt8(pad)
        var ct = aes.encrypt_block(block)
        for i in range(AES_BLOCK_LEN):
            out.append(ct[i])


def _ecb_decrypt_with(
    aes: Aes, ciphertext: Span[UInt8, _], mut out: List[UInt8]
) raises:
    var n = len(ciphertext)
    if n == 0 or n % AES_BLOCK_LEN != 0:
        raise Error("ecb: ciphertext length must be a positive multiple of 16")
    var plain = List[UInt8](capacity=n)
    var block = Array[UInt8, 16](fill=0)
    for off in range(0, n, AES_BLOCK_LEN):
        for i in range(AES_BLOCK_LEN):
            block[i] = ciphertext[off + i]
        var pt = aes.decrypt_block(block)
        for i in range(AES_BLOCK_LEN):
            plain.append(pt[i])

    # Branch-free check that the last byte is 1..16 and that this many
    # trailing bytes all carry the same value.
    var pad = UInt32(plain[n - 1])
    var bad = (16 - pad) >> 31
    bad |= (pad - 1) >> 31
    for i in range(AES_BLOCK_LEN):
        # All ones when byte `n - 1 - i` is part of the padding.
        var in_pad = UInt32(0) - ((UInt32(i) - pad) >> 31)
        bad |= in_pad & (UInt32(plain[n - 1 - i]) ^ pad)
    if bad != 0:
        raise Error("ecb: invalid padding")
    for i in range(n - Int(pad)):
        out.append(plain[i])


def ecb_encrypt_pkcs7(
    key: Span[UInt8, _], plaintext: Span[UInt8, _], mut out: List[UInt8]
) raises:
    """Encrypts with AES-ECB after applying PKCS#7 padding."""
    _ecb_encrypt_with(Aes(key), plaintext, out)


def ecb_decrypt_pkcs7(
    key: Span[UInt8, _], ciphertext: Span[UInt8, _], mut out: List[UInt8]
) raises:
    """Decrypts with AES-ECB and removes PKCS#7 padding.

    When this raises, `out` is left unchanged.
    """
    _ecb_decrypt_with(Aes(key), ciphertext, out)

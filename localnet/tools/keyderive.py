#!/usr/bin/env python3
"""
Pure-python key derivation helpers for the BitVM2 localnet.

No third-party packages (none are installed on this host). Everything is derived
from first principles so that it can be re-checked independently:

  * secp256k1 scalar multiplication      -> BTC compressed / x-only pubkeys, EVM pubkeys
  * keccak-256                           -> EVM (GOAT) addresses
  * bech32 / segwit v0                   -> P2WSH funding addresses (bcrt1q...)
  * base58 / base58check                 -> libp2p PeerId strings, WIF
  * ed25519 (RFC 8032)                   -> libp2p PEER_KEY / PeerId

Every derivation here is cross-checked against the node's own binaries or cast by
tools/gen-keys.sh.
"""
import hashlib

# --------------------------------------------------------------------------- #
# secp256k1
# --------------------------------------------------------------------------- #
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def secp256k1_mul(k, point=G):
    r = None
    while k:
        if k & 1:
            r = _add(r, point)
        point = _add(point, point)
        k >>= 1
    return r


def secp_pubkey(sk_hex):
    """Return (compressed33_hex, xonly32_hex, uncompressed64_hex, prefix_hex)."""
    sk = int(sk_hex, 16)
    if not (0 < sk < N):
        raise ValueError("secret key out of range")
    x, y = secp256k1_mul(sk)
    xs, ys = "%064x" % x, "%064x" % y
    prefix = "02" if y % 2 == 0 else "03"
    return prefix + xs, xs, xs + ys, prefix


# --------------------------------------------------------------------------- #
# keccak-256 (EVM addresses)
# --------------------------------------------------------------------------- #
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]


def _keccak_f(state):
    def rol(v, n):
        return ((v << n) | (v >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

    for rnd in range(24):
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = rol(state[x][y], _KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) & 0xFFFFFFFFFFFFFFFF
        state[0][0] ^= _KECCAK_RC[rnd]
    return state


def keccak256(data: bytes) -> bytes:
    rate = 136  # 1088 bits
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f(state)
    out = bytearray()
    for i in range(4):  # 32 bytes
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


def evm_address(uncompressed64_hex: str) -> str:
    """EIP-55 checksummed address from the 64-byte (x||y) pubkey."""
    h = keccak256(bytes.fromhex(uncompressed64_hex))[-20:].hex()
    cs = keccak256(h.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(cs[i], 16) >= 8 else c
                          for i, c in enumerate(h))


# --------------------------------------------------------------------------- #
# bech32 / segwit v0 (BIP-173)
# --------------------------------------------------------------------------- #
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def segwit_address(hrp, witver, witprog: bytes) -> str:
    data = [witver] + _convertbits(list(witprog), 8, 5)
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def p2wsh_funding_address(compressed_pubkey_hex: str, hrp: str = "bcrt") -> str:
    """Address of the node's funding output: P2WSH(<33B pubkey> OP_CHECKSIG).

    Script is exactly `OP_PUSHBYTES_33 <pubkey> OP_CHECKSIG` (node/src/utils.rs
    node_p2wsh_script/node_p2wsh_address).
    """
    script = bytes([0x21]) + bytes.fromhex(compressed_pubkey_hex) + bytes([0xAC])
    return segwit_address(hrp, 0, hashlib.sha256(script).digest())


# --------------------------------------------------------------------------- #
# base58
# --------------------------------------------------------------------------- #
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def wif(sk_hex: str, network_prefix: int = 0xEF, compressed: bool = True) -> str:
    """WIF for the raw secp256k1 secret (0xEF = regtest/testnet)."""
    payload = bytes([network_prefix]) + bytes.fromhex(sk_hex) + (b"\x01" if compressed else b"")
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)


# --------------------------------------------------------------------------- #
# ed25519 (RFC 8032) -> libp2p PEER_KEY / PeerId
# --------------------------------------------------------------------------- #
_Q = 2**255 - 19
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _ed_xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_ED_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_ED_B = (_ed_xrecover(_ED_BY) % _Q, _ED_BY)


def _ed_add(p, q):
    x1, y1 = p
    x2, y2 = q
    t = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, _Q - 2, _Q)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, _Q - 2, _Q)
    return (x3 % _Q, y3 % _Q)


def _ed_mul(p, e):
    if e == 0:
        return (0, 1)
    q = _ed_mul(p, e // 2)
    q = _ed_add(q, q)
    if e & 1:
        q = _ed_add(q, p)
    return q


def ed25519_pubkey(seed32: bytes) -> bytes:
    h = bytearray(hashlib.sha512(seed32).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    a = int.from_bytes(h, "little")
    x, y = _ed_mul(_ED_B, a)
    enc = bytearray(y.to_bytes(32, "little"))
    enc[31] |= (x & 1) << 7
    return bytes(enc)


def libp2p_peer_key(seed32: bytes):
    """Return (PEER_KEY base64, PEER_ID string, peer-id bytes hex, pubkey hex).

    PEER_KEY  = base64(protobuf PrivateKey{Type=Ed25519(1), Data=seed||pub})
                = base64(08 01 12 40 || seed32 || pub32)     (as produced by
                  `bitvm-noded key peer`, libp2p Keypair::to_protobuf_encoding)
    PeerId    = base58btc( 00 24 08 01 12 20 || pub32 )       (identity multihash
                  over protobuf PublicKey{Type=Ed25519(1), Data=pub32})
    """
    import base64 as _b64
    pub = ed25519_pubkey(seed32)
    proto_priv = bytes([0x08, 0x01, 0x12, 0x40]) + seed32 + pub
    peer_key = _b64.b64encode(proto_priv).decode()
    peer_id_bytes = bytes([0x00, 0x24, 0x08, 0x01, 0x12, 0x20]) + pub
    return peer_key, b58encode(peer_id_bytes), "0x" + peer_id_bytes.hex(), pub.hex()


def peer_id_to_bytes(peer_id: str) -> str:
    return "0x" + b58decode(peer_id).hex()


# --------------------------------------------------------------------------- #
# deterministic role key material
# --------------------------------------------------------------------------- #
DOMAIN = b"bvlocal-localnet-keys-v1"


def derive_secret(master_seed_hex: str, role: str, purpose: str) -> str:
    """32-byte key material, valid as a secp256k1 secret key."""
    seed = bytes.fromhex(master_seed_hex)
    counter = 0
    while True:
        material = hashlib.sha256(
            DOMAIN + b"|" + role.encode() + b"|" + purpose.encode() + b"|"
            + str(counter).encode() + b"|" + seed
        ).digest()
        k = int.from_bytes(material, "big")
        if 0 < k < N:
            return material.hex()
        counter += 1


def selftest():
    assert keccak256(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"abc").hex() == \
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    c, x, u, pfx = secp_pubkey("%064x" % 1)
    assert c == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert evm_address(u) == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    # RFC 8032 test vector 1
    assert ed25519_pubkey(bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).hex() == \
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    # BIP-173 style check of our bech32 encoder via a known node output:
    # BITVM_SECRET=00..01 -> bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry
    assert p2wsh_funding_address(c) == \
        "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry"
    assert b58decode(b58encode(b"\x00\x24hello")) == b"\x00\x24hello"
    return "keyderive selftest OK"


if __name__ == "__main__":
    print(selftest())

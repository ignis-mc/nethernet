"""The TLS 1.2 pseudorandom function (RFC 5246 section 5) with SHA-256."""

from ..crypto.hmac import Hmac
from ..crypto.sha256 import Sha256
from ..wire import put_bytes


def prf_sha256(
    secret: Span[UInt8, _], label: StringSpan, seed: Span[UInt8, _], length: Int
) -> List[UInt8]:
    """Expands a secret into `length` bytes with `P_SHA256`.

    Args:
        secret: The secret to expand.
        label: The ASCII label, for example `key expansion`.
        seed: The seed that follows the label.
        length: The number of output bytes wanted.

    Returns:
        `length` pseudorandom bytes.
    """
    var label_seed = List[UInt8](label.as_bytes())
    put_bytes(label_seed, seed)
    var out = List[UInt8](capacity=length + 32)
    # A(1) = HMAC(secret, label + seed)
    var a_mac = Hmac[Sha256](secret)
    a_mac.update(Span(label_seed))
    var a = a_mac.finish()
    while len(out) < length:
        var block_mac = Hmac[Sha256](secret)
        block_mac.update(Span(a))
        block_mac.update(Span(label_seed))
        var block = block_mac.finish()
        put_bytes(out, Span(block))
        var next_mac = Hmac[Sha256](secret)
        next_mac.update(Span(a))
        a = next_mac.finish()
    out.shrink(length)
    return out^

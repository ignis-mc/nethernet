"""HMAC (RFC 2104) over any `Hash`."""

from .hash import Hash


struct Hmac[H: Hash](Copyable):
    """A streaming HMAC computation.

    Parameters:
        H: The underlying hash function.
    """

    var _inner: Self.H
    var _outer: Self.H

    def __init__(out self, key: Span[UInt8, _]):
        """Creates an HMAC keyed with `key`.

        Args:
            key: The secret key, of any length.
        """
        var block = Array[UInt8, Self.H.BLOCK_SIZE](fill=0)
        if len(key) > Self.H.BLOCK_SIZE:
            var kh = Self.H()
            kh.update(key)
            var digest = kh.finish()
            for i in range(Self.H.DIGEST_SIZE):
                block[i] = digest[i]
        else:
            for i in range(len(key)):
                block[i] = key[i]
        var ipad = Array[UInt8, Self.H.BLOCK_SIZE](fill=0)
        var opad = Array[UInt8, Self.H.BLOCK_SIZE](fill=0)
        for i in range(Self.H.BLOCK_SIZE):
            ipad[i] = block[i] ^ 0x36
            opad[i] = block[i] ^ 0x5C
        self._inner = Self.H()
        self._inner.update(Span(ipad))
        self._outer = Self.H()
        self._outer.update(Span(opad))

    def update(mut self, data: Span[UInt8, _]):
        """Absorbs more message bytes.

        Args:
            data: The bytes to authenticate.
        """
        self._inner.update(data)

    def finish(mut self) -> Array[UInt8, Self.H.DIGEST_SIZE]:
        """Produces the authentication tag.

        The value must not be used again afterwards.

        Returns:
            The tag, as long as the hash digest.
        """
        var inner_digest = self._inner.finish()
        self._outer.update(Span(inner_digest))
        return self._outer.finish()


def hmac[H: Hash](
    key: Span[UInt8, _], message: Span[UInt8, _]
) -> Array[UInt8, H.DIGEST_SIZE]:
    """Computes HMAC of `message` under `key`.

    Parameters:
        H: The underlying hash function.

    Args:
        key: The secret key, of any length.
        message: The bytes to authenticate.

    Returns:
        The tag, as long as the hash digest.
    """
    var mac = Hmac[H](key)
    mac.update(message)
    return mac.finish()

"""The `Hash` trait shared by the SHA family and consumed by HMAC."""


trait Hash(Copyable, Defaultable, Deinitable):
    """A streaming cryptographic hash function.

    A default-constructed value is ready to absorb input. Call `update()` any
    number of times, then `finish()` once.
    """

    comptime BLOCK_SIZE: Int
    """The internal block size in bytes, used by HMAC."""
    comptime DIGEST_SIZE: Int
    """The digest size in bytes."""

    def update(mut self, data: Span[UInt8, _]):
        """Absorbs more input.

        Args:
            data: The bytes to hash.
        """
        ...

    def finish(mut self) -> Array[UInt8, Self.DIGEST_SIZE]:
        """Pads the input and produces the digest.

        The hasher must not be used again afterwards.

        Returns:
            The digest.
        """
        ...

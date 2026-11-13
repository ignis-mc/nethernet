"""Error causes and the chunks that carry them: ABORT and ERROR."""

from ..wire import put_bytes
from .packet import (
    CHUNK_ABORT,
    CHUNK_ERROR,
    begin_chunk,
    begin_param,
    end_chunk,
    end_param,
    parse_tlvs,
)

comptime CAUSE_INVALID_STREAM = 1
"""Error cause: Invalid Stream Identifier."""
comptime CAUSE_STALE_COOKIE = 3
"""Error cause: Stale Cookie."""
comptime CAUSE_OUT_OF_RESOURCE = 4
"""Error cause: Out of Resource."""
comptime CAUSE_UNRECOGNIZED_CHUNK = 6
"""Error cause: Unrecognized Chunk Type."""
comptime CAUSE_INVALID_MANDATORY_PARAMETER = 7
"""Error cause: Invalid Mandatory Parameter."""
comptime CAUSE_NO_USER_DATA = 9
"""Error cause: No User Data."""
comptime CAUSE_USER_INITIATED_ABORT = 12
"""Error cause: User-Initiated Abort."""
comptime CAUSE_PROTOCOL_VIOLATION = 13
"""Error cause: Protocol Violation."""


struct ErrorCause(Copyable):
    """One error cause of an ABORT or ERROR chunk."""

    var code: UInt16
    """The cause code, such as `CAUSE_USER_INITIATED_ABORT`."""
    var info: List[UInt8]
    """The cause-specific information."""

    def __init__(out self, code: UInt16, info: Span[UInt8, _]):
        """Creates a cause, copying its information.

        Args:
            code: The cause code.
            info: The cause-specific information.
        """
        self.code = code
        self.info = List[UInt8](info)


def decode_causes(value: Span[UInt8, _]) raises -> List[ErrorCause]:
    """Decodes the error causes of an ABORT or ERROR chunk.

    Args:
        value: The chunk value.

    Returns:
        The causes in wire order.

    Raises:
        Error: If a cause is truncated.
    """
    var causes = List[ErrorCause]()
    var items = parse_tlvs(value, 0)
    for item in items:
        causes.append(
            ErrorCause(
                item.kind, value[item.offset : item.offset + item.length]
            )
        )
    return causes^


def _encode_causes(
    mut out: List[UInt8], kind: UInt8, flags: UInt8, causes: Span[ErrorCause, _]
):
    var start = begin_chunk(out, kind, flags)
    for c in causes:
        var p = begin_param(out, start, c.code)
        put_bytes(out, Span(c.info))
        end_param(out, p)
    end_chunk(out, start)


def encode_abort(
    mut out: List[UInt8], t_bit: Bool, causes: Span[ErrorCause, _]
):
    """Appends an ABORT chunk.

    Args:
        out: The buffer to append to.
        t_bit: Whether the packet reflects the peer's verification tag
            instead of carrying the tag the peer expects.
        causes: The error causes to report.
    """
    _encode_causes(out, CHUNK_ABORT, UInt8(1) if t_bit else UInt8(0), causes)


def encode_error(mut out: List[UInt8], causes: Span[ErrorCause, _]):
    """Appends an ERROR chunk.

    Args:
        out: The buffer to append to.
        causes: The error causes to report.
    """
    _encode_causes(out, CHUNK_ERROR, 0, causes)

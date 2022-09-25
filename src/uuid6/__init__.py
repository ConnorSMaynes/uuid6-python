r"""UUID draft version objects (universally unique identifiers).
This module provides the functions uuid6() and uuid7() for
generating version 6 and 7 UUIDs as specified in
https://github.com/uuid6/uuid6-ietf-draft.
"""

import secrets
import time
import uuid
from typing import Tuple
import threading


class UUID(uuid.UUID):
    r"""UUID draft version objects"""

    def __init__(
        self,
        hex: str = None,
        bytes: bytes = None,
        bytes_le: bytes = None,
        fields: Tuple[int, int, int, int, int, int] = None,
        int: int = None,
        version: int = None,
        *,
        is_safe=uuid.SafeUUID.unknown
    ) -> None:
        r"""Create a UUID."""

        if int is None or [hex, bytes, bytes_le, fields].count(None) != 4:
            return super().__init__(
                hex=hex,
                bytes=bytes,
                bytes_le=bytes_le,
                fields=fields,
                int=int,
                version=version,
                is_safe=is_safe,
            )
        if not 0 <= int < 1 << 128:
            raise ValueError("int is out of range (need a 128-bit value)")
        if version is not None:
            if not 6 <= version <= 7:
                raise ValueError("illegal version number")
            # Set the variant to RFC 4122.
            int &= ~(0xC000 << 48)
            int |= 0x8000 << 48
            # Set the version number.
            int &= ~(0xF000 << 64)
            int |= version << 76
        super().__init__(int=int, is_safe=is_safe)

    @property
    def subsec(self) -> int:
        return ((self.int >> 64) & 0x0FFF) << 8 | ((self.int >> 54) & 0xFF)

    @property
    def time(self) -> int:
        if self.version == 7:
            return (self.int >> 80) * 10**6 + _subsec_decode(self.subsec)
        return super().time


def _subsec_decode(value: int) -> int:
    return -(-value * 10**6 // 2**20)


def _subsec_encode(value: int) -> int:
    return value * 2**20 // 10**6


_v7_lock = threading.RLock()
_last_v7_timestamp = None


def uuid7() -> UUID:
    r"""UUID version 7 features a time-ordered value field derived from the
    widely implemented and well known Unix Epoch timestamp source, the
    number of milliseconds seconds since midnight 1 Jan 1970 UTC, leap
    seconds excluded.  As well as improved entropy characteristics over
    versions 1 or 6.

    Implementations SHOULD utilize UUID version 7 over UUID version 1 and
    6 if possible."""
    global _v7_lock
    global _last_v7_timestamp

    nanoseconds = time.time_ns()
    with _v7_lock:
        if _last_v7_timestamp is not None and nanoseconds <= _last_v7_timestamp:
            nanoseconds = _last_v7_timestamp + 1
        _last_v7_timestamp = nanoseconds
    timestamp_ms, timestamp_ns = divmod(nanoseconds, 10**6)
    subsec = _subsec_encode(timestamp_ns)
    subsec_a = subsec >> 8
    subsec_b = subsec & 0xFF
    rand = secrets.randbits(54)
    uuid_int = (timestamp_ms & 0xFFFFFFFFFFFF) << 80
    uuid_int |= subsec_a << 64
    uuid_int |= subsec_b << 54
    uuid_int |= rand
    return UUID(int=uuid_int, version=7)

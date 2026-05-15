"""Shared exceptions for I/O, framing, and atomic commit helpers."""


class CommonIOError(Exception):
    """Base class for recoverable helper-layer failures."""


class ConnectionClosedError(CommonIOError):
    """Peer closed the connection before the expected number of bytes arrived."""


class FrameTooLargeError(CommonIOError):
    """Length-prefix declared a payload larger than the configured maximum."""


class FramingError(CommonIOError):
    """Malformed length prefix or payload that cannot be decoded."""


class AtomicCommitError(CommonIOError):
    """Rename/promotion of a verified partial file failed."""

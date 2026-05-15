"""Shared utilities for both transfer approaches."""

from common.atomic_io import commit_verified_part, part_path_for, replace_with_final
from common.constants import (
    DEFAULT_CHUNK_SIZE_BYTES,
    DEFAULT_CONNECT_TIMEOUT_SEC,
    DEFAULT_READ_TIMEOUT_SEC,
    DEFAULT_SOCKET_BUFFER_BYTES,
    DEFAULT_WRITE_TIMEOUT_SEC,
    LENGTH_PREFIX_BYTES,
    MAX_BINARY_PAYLOAD_BYTES,
    MAX_JSON_PAYLOAD_BYTES,
)
from common.errors import (
    AtomicCommitError,
    CommonIOError,
    ConnectionClosedError,
    FrameTooLargeError,
    FramingError,
)
from common.framing import recv_binary_frame, recv_json_frame, send_binary_frame, send_json_frame
from common.hashing import StreamingSha256, sha256_hex_digest_file, verify_file_sha256_hex
from common.streaming import (
    iter_file_chunks,
    iter_fixed_chunks_from_stream,
    read_exact_stream,
    write_chunks_to_stream,
)
from common.temp_files import open_part_file, open_unique_temp_in_final_dir, try_unlink
from common.tcp import (
    apply_socket_buffer_hints,
    configure_blocking_socket,
    recv_exact,
    send_all,
    with_connect_timeout,
)

__all__ = [
    "AtomicCommitError",
    "CommonIOError",
    "ConnectionClosedError",
    "DEFAULT_CHUNK_SIZE_BYTES",
    "DEFAULT_CONNECT_TIMEOUT_SEC",
    "DEFAULT_READ_TIMEOUT_SEC",
    "DEFAULT_SOCKET_BUFFER_BYTES",
    "DEFAULT_WRITE_TIMEOUT_SEC",
    "FrameTooLargeError",
    "FramingError",
    "LENGTH_PREFIX_BYTES",
    "MAX_BINARY_PAYLOAD_BYTES",
    "MAX_JSON_PAYLOAD_BYTES",
    "StreamingSha256",
    "apply_socket_buffer_hints",
    "commit_verified_part",
    "configure_blocking_socket",
    "iter_file_chunks",
    "iter_fixed_chunks_from_stream",
    "open_part_file",
    "open_unique_temp_in_final_dir",
    "part_path_for",
    "read_exact_stream",
    "recv_binary_frame",
    "recv_exact",
    "recv_json_frame",
    "replace_with_final",
    "send_all",
    "send_binary_frame",
    "send_json_frame",
    "sha256_hex_digest_file",
    "try_unlink",
    "verify_file_sha256_hex",
    "with_connect_timeout",
    "write_chunks_to_stream",
]

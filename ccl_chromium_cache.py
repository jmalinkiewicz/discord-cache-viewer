"""
Copyright 2022-2025, CCL Forensics

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import abc
import dataclasses
import io
import os
import re
import sys
import types
import typing
import pathlib
import datetime
import struct
import enum
import zlib
import csv
import hashlib
import mimetypes
import brotli
import gzip

__version__ = "0.22"
__description__ = "Library for reading Chrome/Chromium Cache (both blockfile and simple format)"
__contact__ = "Alex Caithness"


_CHROME_EPOCH = datetime.datetime(1601, 1, 1)
EIGHT_BYTE_PICKLE_ALIGNMENT = True
SIMPLE_EOF_SIZE = 24 if EIGHT_BYTE_PICKLE_ALIGNMENT else 20


def decode_chrome_time(us: int) -> datetime.datetime:
    return _CHROME_EPOCH + datetime.timedelta(microseconds=us)


class BinaryReader:
    def __init__(self, stream: typing.BinaryIO):
        self._stream = stream
        self._closed = False

    @classmethod
    def from_bytes(cls, buffer: bytes):
        return cls(io.BytesIO(buffer))

    def close(self):
        self._stream.close()
        self._closed = True

    def __enter__(self) -> "BinaryReader":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def tell(self) -> int:
        return self._stream.tell()

    def seek(self, offset: int, whence: int) -> int:
        return self._stream.seek(offset, whence)

    def read_raw(self, count: int) -> bytes:
        start_offset = self._stream.tell()
        result = self._stream.read(count)
        if len(result) != count:
            raise ValueError(
                f"Could not read all of the data starting at {start_offset}. Expected: {count}; got {len(result)}")
        return result

    def read_utf8(self, count: int) -> str:
        return self.read_raw(count).decode("utf-8")

    def read_int16(self) -> int:
        raw = self.read_raw(2)
        return struct.unpack("<h", raw)[0]

    def read_int32(self) -> int:
        raw = self.read_raw(4)
        return struct.unpack("<i", raw)[0]

    def read_int64(self) -> int:
        raw = self.read_raw(8)
        return struct.unpack("<q", raw)[0]

    def read_uint16(self) -> int:
        raw = self.read_raw(2)
        return struct.unpack("<H", raw)[0]

    def read_uint32(self) -> int:
        raw = self.read_raw(4)
        return struct.unpack("<I", raw)[0]

    def read_uint64(self) -> int:
        raw = self.read_raw(8)
        return struct.unpack("<Q", raw)[0]

    def read_addr(self) -> "Addr":
        return Addr.from_int(self.read_uint32())

    def read_datetime(self) -> datetime.datetime:
        return decode_chrome_time(self.read_uint64())

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def is_eof(self) -> bool:
        test = self._stream.read(1)
        if len(test) == 0:
            return True
        self._stream.seek(-1, os.SEEK_CUR)
        return False


class FileType(enum.IntEnum):
    EXTERNAL = 0
    RANKINGS = 1
    BLOCK_256 = 2
    BLOCK_1K = 3
    BLOCK_4K = 4
    BLOCK_FILES = 5
    BLOCK_ENTRIES = 6
    BLOCK_EVICTED = 7


_BLOCKSIZE_FOR_FILETYPE = {
    FileType.RANKINGS: 36,
    FileType.BLOCK_256: 256,
    FileType.BLOCK_1K: 1024,
    FileType.BLOCK_4K: 4096,
    FileType.BLOCK_FILES: 8,
    FileType.BLOCK_ENTRIES: 104,
    FileType.BLOCK_EVICTED: 48,
    FileType.EXTERNAL: 0
}


_BLOCK_FILE_FILETYPE = {FileType.BLOCK_256, FileType.BLOCK_1K, FileType.BLOCK_4K}


class CacheKey:
    CRED_UPLOAD_KEY_PREFIX_PATTERN = re.compile(r"^\d+/\d+/")
    UPLOAD_ONLY_KEY_PREFIX_PATTERN = re.compile(r"^\d+/")

    def __init__(self, raw_key: str):
        self._raw_key = raw_key

        if CacheKey.UPLOAD_ONLY_KEY_PREFIX_PATTERN.match(self._raw_key):
            if CacheKey.CRED_UPLOAD_KEY_PREFIX_PATTERN.match(self._raw_key):
                split_key = self._raw_key.split("/", 2)
                self._credential_key = split_key[0]
                self._upload_data_identifier = int(split_key[1])
            else:
                split_key = self._raw_key.split("/", 1)
                self._credential_key = ""
                self._upload_data_identifier = int(split_key[0])

            if split_key[-1].startswith("_dk_"):
                (self._isolation_key_top_frame_site,
                 self._isolation_key_variable_part,
                 self._url) = split_key[-1][4:].split(" ", 3)
                if self._isolation_key_top_frame_site.startswith("s_"):
                    self._isolation_key_top_frame_site = self._isolation_key_top_frame_site[2:]
            else:
                self._url = split_key[-1]
                self._isolation_key_top_frame_site = None
                self._isolation_key_variable_part = None
        else:
            self._url = self._raw_key
            self._isolation_key_top_frame_site = None
            self._isolation_key_variable_part = None

    @property
    def raw_key(self) -> str:
        return self._raw_key

    @property
    def url(self) -> str:
        return self._url

    @property
    def credential_key(self) -> str:
        return self._credential_key

    @property
    def upload_data_identifier(self) -> int:
        return self._upload_data_identifier

    @property
    def isolation_key_top_frame_site(self) -> str:
        return self._isolation_key_top_frame_site

    @property
    def isolation_key_variable_part(self):
        return self._isolation_key_variable_part

    def __str__(self):
        return self._raw_key

    def __repr__(self):
        return (f"<CacheKey url: {self._url}; credential_key: {self._credential_key}; "
                f"upload_data_identifier: {self._upload_data_identifier}; "
                f"isolation_key_top_frame_site: {self._isolation_key_top_frame_site}; "
                f"isolation_key_variable_part: {self._isolation_key_variable_part}>")


class Addr:
    def __init__(
            self, is_initialized: bool, file_type: FileType, file_number: typing.Optional[int],
            contiguous_blocks: typing.Optional[int], file_selector: typing.Optional[int], block_number: int,
            reserved_bits: typing.Optional[int]):
        self._is_initialized = is_initialized
        self._file_type = file_type
        self._file_number = file_number
        self._contiguous_blocks = contiguous_blocks
        self._file_selector = file_selector
        self._block_number = block_number
        self._reserved_bits = reserved_bits

    def __repr__(self):
        return (f"<Addr: is_initialized: {self._is_initialized}; file_type: {self._file_type.name}; "
                f"file_number: {self._file_number}; contiguous_blocks: {self._contiguous_blocks}; "
                f"file_selector: {self._file_selector}; block_number: {self._block_number}>")

    @classmethod
    def from_int(cls, i: int):
        is_initialized = (i & 0x80000000) > 0
        file_type = FileType((i & 0x70000000) >> 28)

        if file_type == FileType.EXTERNAL:
            file_number = i & 0x0fffffff
            contiguous_blocks = None
            file_selector = None
            block_number = None
            reserved_bits = None
        else:
            file_number = None
            contiguous_blocks = 1 + ((i & 0x03000000) >> 24)
            file_selector = (i & 0x00ff0000) >> 16
            block_number = i & 0x0000ffff
            reserved_bits = i & 0x0c000000

        return Addr(
            is_initialized,
            file_type,
            file_number,
            contiguous_blocks,
            file_selector,
            block_number,
            reserved_bits)

    def sanity_check(self) -> bool:
        if self._file_type > FileType.BLOCK_4K:
            return False
        if self._file_type != FileType.EXTERNAL and self._reserved_bits != 0:
            return False

        return True

    def sanity_check_for_entry(self) -> bool:
        return self.sanity_check() and self._file_type == FileType.BLOCK_256

    @property
    def is_initialized(self) -> bool:
        return self._is_initialized

    @property
    def file_type(self) -> FileType:
        return self._file_type

    @property
    def contiguous_blocks(self) -> int:
        return self._contiguous_blocks

    @property
    def file_selector(self) -> int:
        return self._file_selector

    @property
    def block_number(self) -> int:
        return self._block_number

    @property
    def external_file_number(self) -> int:
        return self._file_number


@dataclasses.dataclass(frozen=True)
class LruData:
    filled: int
    sizes: typing.Collection[int]
    heads: typing.Collection[Addr]
    tails: typing.Collection[Addr]
    transactions: Addr
    operation: int
    operation_list: int

    @classmethod
    def from_bytes(cls, buffer: bytes):
        with BinaryReader.from_bytes(buffer) as reader:
            return cls.from_reader(reader)

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        _ = [reader.read_int32() for x in range(2)]
        filled = reader.read_int32()
        sizes = tuple(reader.read_int32() for _ in range(5))
        heads = tuple(reader.read_addr() for _ in range(5))
        tails = tuple(reader.read_addr() for _ in range(5))
        transaction = reader.read_addr()
        operation = reader.read_int32()
        operation_list = reader.read_int32()
        _ = [reader.read_int32() for x in range(7)]

        return cls(filled, sizes, heads, tails, transaction, operation, operation_list)


@dataclasses.dataclass(frozen=True)
class BlockFileIndexHeader:
    version: int
    num_entries: int
    num_bytes_v2: int
    last_file: int
    this_id: int
    stats_addr: Addr
    table_length: int
    crash: int
    experiment: int
    create_time: datetime.datetime
    num_bytes_v3: int
    lru: LruData

    _MAGIC: typing.ClassVar[int] = 0xC103CAC3

    @classmethod
    def from_bytes(cls, buffer: bytes):
        with BinaryReader.from_bytes(buffer) as reader:
            return cls.from_reader(reader)

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        magic = reader.read_uint32()
        if magic != BlockFileIndexHeader._MAGIC:
            raise ValueError("invalid magic")
        version = reader.read_uint32()
        num_entries = reader.read_int32()
        old_v2_num_bytes = reader.read_uint32()
        last_file = reader.read_int32()
        this_id = reader.read_int32()
        stats_addr = reader.read_addr()
        table_length = reader.read_int32() or 0x10000
        crash = reader.read_int32()
        experiment = reader.read_int32()
        create_time = reader.read_datetime()
        num_bytes = reader.read_int64()
        _ = [reader.read_int32() for x in range(50)]
        lru = LruData.from_reader(reader)

        return cls(
            version, num_entries, old_v2_num_bytes, last_file, this_id, stats_addr,
            table_length, crash, experiment, create_time, num_bytes, lru)


class BlockFileIndexFile:
    def __init__(self, file_path: typing.Union[os.PathLike, str]):
        self._input_path = pathlib.Path(file_path)
        with BinaryReader(self._input_path.open("rb")) as reader:
            self._header = BlockFileIndexHeader.from_reader(reader)
            self._entries = tuple(reader.read_addr() for _ in range(self._header.table_length))
            self._entries_initialized = tuple(x for x in self._entries if x.is_initialized)

    @property
    def input_path(self):
        return self._input_path

    @property
    def header(self) -> BlockFileIndexHeader:
        return self._header

    @property
    def index(self) -> typing.Collection[Addr]:
        return self._entries

    @property
    def index_initialized_only(self):
        return self._entries_initialized


class EntryState(enum.IntEnum):
    NORMAL = 0
    EVICTED = 1
    DOOMED = 2


class EntryFlags(enum.IntFlag):
    PARENT_ENTRY = 1 << 0
    CHILD_ENTRY = 1 << 1


@dataclasses.dataclass(frozen=True)
class EntryStore:
    entry_hash: int
    next_entry: Addr
    rankings_node: Addr
    reuse_count: int
    refetch_count: int
    state: EntryState
    creation_time: datetime.datetime
    key_length: int
    long_key_addr: Addr
    data_sizes: tuple[int, int, int, int]
    data_addrs: tuple[Addr, Addr, Addr, Addr]
    flags: EntryFlags
    self_hash: int
    key: typing.Optional[str]

    @property
    def key_is_external(self) -> bool:
        return self.long_key_addr.is_initialized

    @classmethod
    def from_bytes(cls, buffer: bytes):
        with BinaryReader.from_bytes(buffer) as reader:
            return cls.from_reader(reader)

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        start = reader.tell()

        entry_hash = reader.read_uint32()
        next_entry = reader.read_addr()
        rankings_node = reader.read_addr()
        reuse_count = reader.read_int32()
        refetch_count = reader.read_int32()
        state = EntryState(reader.read_int32())
        creation_time = reader.read_datetime()
        key_length = reader.read_int32()
        long_key_addr = reader.read_addr()
        data_sizes = (reader.read_int32(), reader.read_int32(), reader.read_int32(), reader.read_int32())
        data_addrs = (reader.read_addr(), reader.read_addr(), reader.read_addr(), reader.read_addr())
        flags = EntryFlags(reader.read_uint32())
        _ = [reader.read_int32() for x in range(4)]
        self_hash = reader.read_uint32()

        meta_length = reader.tell() - start

        key = None
        key_is_external = long_key_addr.is_initialized
        if not key_is_external:
            key = reader.read_utf8(key_length)

        return cls(
            entry_hash, next_entry, rankings_node, reuse_count, refetch_count, state, creation_time, key_length,
            long_key_addr, data_sizes, data_addrs, flags, self_hash, key)


@dataclasses.dataclass(frozen=True)
class BlockFileHeader:
    version: int
    this_file: int
    next_file: int
    entry_size: int
    num_entries: int
    max_entries: int
    empty_type_counts: tuple[int, int, int, int]
    hints: tuple[int, int, int, int]
    updating: int
    user: tuple[int, int, int, int, int]
    allocation_map: bytes

    _MAGIC: typing.ClassVar[int] = 0xC104CAC3
    _BLOCK_HEADER_SIZE: typing.ClassVar[int] = 8192
    _MAX_BLOCKS: typing.ClassVar[int] = (_BLOCK_HEADER_SIZE - 80) * 8

    def __post_init__(self):
        if len(self.allocation_map) != self._MAX_BLOCKS // 8:
            raise ValueError("invalid allocation map length")

    @classmethod
    def from_bytes(cls, buffer: bytes):
        with BinaryReader.from_bytes(buffer) as reader:
            return cls.from_reader(reader)

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        magic = reader.read_uint32()
        if magic != cls._MAGIC:
            raise ValueError("invalid magic")
        version = reader.read_uint32()
        this_file = reader.read_int16()
        next_file = reader.read_int16()
        entry_size = reader.read_int32()
        num_entries = reader.read_int32()
        max_entries = reader.read_int32()
        empty = (reader.read_int32(), reader.read_int32(), reader.read_int32(), reader.read_int32())
        hints = (reader.read_int32(), reader.read_int32(), reader.read_int32(), reader.read_int32())
        updating = reader.read_int32()
        user = (reader.read_int32(), reader.read_int32(), reader.read_int32(), reader.read_int32(), reader.read_int32())

        allocation_map = reader.read_raw(cls._MAX_BLOCKS // 8)

        return cls(
            version, this_file, next_file, entry_size, num_entries, max_entries,
            empty, hints, updating, user, allocation_map)


class CachedMetadataFlags(enum.IntFlag):
    RESPONSE_INFO_VERSION = 3
    RESPONSE_INFO_VERSION_MASK = 0xFF

    RESPONSE_INFO_HAS_CERT = 1 << 8
    RESPONSE_INFO_HAS_SECURITY_BITS = 1 << 9
    RESPONSE_INFO_HAS_CERT_STATUS = 1 << 10
    RESPONSE_INFO_HAS_VARY_DATA = 1 << 11
    RESPONSE_INFO_TRUNCATED = 1 << 12
    RESPONSE_INFO_WAS_SPDY = 1 << 13
    RESPONSE_INFO_WAS_ALPN = 1 << 14
    RESPONSE_INFO_WAS_PROXY = 1 << 15
    RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS = 1 << 16
    RESPONSE_INFO_HAS_ALPN_NEGOTIATED_PROTOCOL = 1 << 17
    RESPONSE_INFO_HAS_CONNECTION_INFO = 1 << 18
    RESPONSE_INFO_USE_HTTP_AUTHENTICATION = 1 << 19
    RESPONSE_INFO_HAS_SIGNED_CERTIFICATE_TIMESTAMPS = 1 << 20
    RESPONSE_INFO_UNUSED_SINCE_PREFETCH = 1 << 21
    RESPONSE_INFO_HAS_KEY_EXCHANGE_GROUP = 1 << 22
    RESPONSE_INFO_PKP_BYPASSED = 1 << 23
    RESPONSE_INFO_HAS_STALENESS = 1 << 24
    RESPONSE_INFO_HAS_PEER_SIGNATURE_ALGORITHM = 1 << 25
    RESPONSE_INFO_RESTRICTED_PREFETCH = 1 << 26
    RESPONSE_INFO_HAS_DNS_ALIASES = 1 << 27
    RESPONSE_INFO_SINGLE_KEYED_CACHE_ENTRY_UNUSABLE = 1 << 28
    RESPONSE_INFO_ENCRYPTED_CLIENT_HELLO = 1 << 29
    RESPONSE_INFO_BROWSER_RUN_ID = 1 << 30
    RESPONSE_INFO_HAS_EXTRA_FLAGS = 1 << 31


class CachedMetadataExtraFlags(enum.IntFlag):
    RESPONSE_EXTRA_INFO_DID_USE_SHARED_DICTIONARY = 1
    RESPONSE_EXTRA_INFO_HAS_PROXY_CHAIN = 1 << 1
    RESPONSE_EXTRA_INFO_HAS_ORIGINAL_RESPONSE_TIME = 1 << 2


class CachedMetadata:
    def __init__(
            self, header_declarations: set[str], header_attributes: dict[str, list[str]],
            request_time: datetime.datetime, response_time: datetime.datetime, certs: list[bytes],
            host_address: str, hot_port: int, other_attributes: dict[str, typing.Any]):
        self._declarations = header_declarations.copy()
        self._attributes = types.MappingProxyType(header_attributes.copy())
        self._request_time = request_time
        self._response_time = response_time
        self._certs = certs.copy()
        self._other_attributes = types.MappingProxyType(other_attributes)
        self._host_address = host_address
        self._host_port = hot_port

    @property
    def certs(self) -> typing.Iterable[bytes]:
        yield from self._certs

    @property
    def http_header_declarations(self) -> typing.Iterable[str]:
        yield from self._declarations

    @property
    def request_time(self) -> datetime.datetime:
        return self._request_time

    @property
    def response_time(self) -> datetime.datetime:
        return self._response_time

    @property
    def http_header_attributes(self) -> typing.Iterable[tuple[str, str]]:
        for key, vals in self._attributes.items():
            for val in vals:
                yield key, val

    def has_declaration(self, declaration: str) -> bool:
        return declaration in self._declarations

    def get_attribute(self, attribute: str) -> list[str]:
        return self._attributes.get(attribute.lower()) or []

    @property
    def other_cache_attributes(self):
        return self._other_attributes

    @classmethod
    def from_buffer(cls, buffer: bytes):
        reader = BinaryReader.from_bytes(buffer)
        total_length = reader.read_uint32()
        if total_length != len(buffer) - 4:
            raise ValueError("Metadata buffer is not the declared size")

        def align():
            alignment = reader.tell() % 4
            if alignment != 0:
                reader.read_raw(4 - alignment)

        flags = CachedMetadataFlags(reader.read_uint32())
        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_EXTRA_FLAGS:
            extra_flags = CachedMetadataExtraFlags(reader.read_uint32())
        else:
            extra_flags = CachedMetadataExtraFlags(0)

        request_time = reader.read_datetime()
        response_time = reader.read_datetime()

        if extra_flags & CachedMetadataExtraFlags.RESPONSE_EXTRA_INFO_HAS_ORIGINAL_RESPONSE_TIME:
            original_response_time = reader.read_datetime()

        http_header_length = reader.read_uint32()
        http_header_raw = reader.read_raw(http_header_length)

        header_attributes: dict[str, list[str]] = {}
        header_declarations = set()

        for header_entry in http_header_raw.split(b"\00"):
            if not header_entry:
                continue
            parsed_entry = header_entry.decode("latin-1").split(":", 1)
            if len(parsed_entry) == 1:
                header_declarations.add(parsed_entry[0])
            elif len(parsed_entry) == 2:
                header_attributes.setdefault(parsed_entry[0].lower(), [])
                header_attributes[parsed_entry[0].lower()].append(parsed_entry[1].strip())

        other_attributes = {}

        certs = []
        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_CERT:
            align()
            cert_count = reader.read_uint32()
            for _ in range(cert_count):
                align()
                cert_length = reader.read_uint32()
                certs.append(reader.read_raw(cert_length))

        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_CERT_STATUS:
            align()
            other_attributes["cert_status"] = reader.read_uint32()

        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_SECURITY_BITS:
            align()
            other_attributes["security_bits"] = reader.read_int32()

        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS:
            align()
            other_attributes["ssl_connection_status"] = reader.read_int32()

        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_SIGNED_CERTIFICATE_TIMESTAMPS:
            align()
            ts_count = reader.read_int32()
            for _ in range(ts_count):
                ts_version = reader.read_int32()
                str_len = reader.read_int32()
                ts_log_id = reader.read_raw(str_len)
                align()
                ts_timestamp = reader.read_datetime()
                str_len = reader.read_int32()
                ts_extensions = reader.read_raw(str_len)
                align()
                ts_hash_algo = reader.read_int32()
                ts_sig_algo = reader.read_int32()
                str_len = reader.read_int32()
                ts_sig_data = reader.read_raw(str_len)
                align()
                ts_origin = reader.read_int32()
                str_len = reader.read_int32()
                ts_log_desc = reader.read_raw(str_len)
                align()
                ts_status = reader.read_uint16()
                align()

        if flags & CachedMetadataFlags.RESPONSE_INFO_HAS_VARY_DATA:
            align()
            other_attributes["vary_data"] = reader.read_raw(16)

        host, port = None, None
        try:
            align()
            host_length = reader.read_uint32()
            host = reader.read_raw(host_length).decode("latin-1")
            align()
            port = reader.read_uint16()
        except ValueError:
            return cls(
                header_declarations, header_attributes, request_time, response_time, certs, host, port,
                other_attributes)

        return cls(
            header_declarations, header_attributes, request_time, response_time, certs, host, port, other_attributes)


@dataclasses.dataclass(frozen=True)
class CacheFileLocation:
    file_name: str
    offset: int

    def __repr__(self):
        return f"<CacheFileLocation; file_name: '{self.file_name}'; offset: {self.offset}"

    def __str__(self):
        return f"{self.file_name} @ {self.offset}"


class ChromiumCache(abc.ABC):
    def get_metadata(self, key: typing.Union[str, CacheKey]) -> list[typing.Optional[CachedMetadata]]:
        raise NotImplementedError()

    def get_cachefile(self, key: typing.Union[str, CacheKey]) -> list[bytes]:
        raise NotImplementedError()

    def get_location_for_metadata(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        raise NotImplementedError()

    def get_location_for_cachefile(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        raise NotImplementedError()

    def __enter__(self) -> "ChromiumCache":
        raise NotImplementedError()

    def __exit__(self, exc_type, exc_val, exc_tb):
        raise NotImplementedError()

    def keys(self) -> typing.Iterable[str]:
        raise NotImplementedError()

    def cache_keys(self) -> typing.Iterable[CacheKey]:
        raise NotImplementedError()


class ChromiumBlockFileCache(ChromiumCache):
    def __init__(self, cache_dir: typing.Union[os.PathLike, str]):
        self._in_dir = pathlib.Path(cache_dir)
        self._index_file = BlockFileIndexFile(self._in_dir / "index")
        self._block_files: dict[int, tuple[BlockFileHeader, typing.BinaryIO]] = {}
        self._keys = self._build_keys()

    def _get_block_file(self, block_file_number: int) -> tuple[BlockFileHeader, typing.BinaryIO]:
        if cached := self._block_files.get(block_file_number):
            return cached

        block_file_stream = (self._in_dir / f"data_{block_file_number}").open("rb")
        header = BlockFileHeader.from_bytes(block_file_stream.read(BlockFileHeader._BLOCK_HEADER_SIZE))
        self._block_files[block_file_number] = (header, block_file_stream)
        return header, block_file_stream

    def _build_keys(self):
        result = {}
        for addr in self._index_file.index:
            while addr.is_initialized:
                if not addr.sanity_check_for_entry():
                    break
                raw = self.get_data_for_addr(addr)
                try:
                    es = EntryStore.from_bytes(raw)
                except (ValueError, OverflowError):
                    break
                if es.key is not None:
                    key = es.key
                else:
                    key = self.get_data_for_addr(es.long_key_addr).decode("utf-8")[0:es.key_length]

                result[key] = es
                addr = es.next_entry

        return result

    def _get_location(self, key: str, stream_number: int):
        es = self._keys[key]
        addr = es.data_addrs[stream_number]
        if addr.file_type in _BLOCK_FILE_FILETYPE:
            file_name = f"data_{addr.file_selector}"
            block_header, stream = self._get_block_file(addr.file_selector)
            offset = BlockFileHeader._BLOCK_HEADER_SIZE + (block_header.entry_size * addr.block_number)
            return CacheFileLocation(file_name, offset)
        elif addr.file_type == FileType.EXTERNAL:
            file_name = f"f_{addr.external_file_number:06x}"
            return CacheFileLocation(file_name, 0)

        raise ValueError("unexpected file type")

    def get_location_for_metadata(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        if isinstance(key, CacheKey):
            key = key.raw_key
        return [self._get_location(key, 0)]

    def get_location_for_cachefile(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        if isinstance(key, CacheKey):
            key = key.raw_key
        return [self._get_location(key, 1)]

    def get_stream_for_addr(self, addr: Addr) -> typing.BinaryIO:
        if not addr.is_initialized:
            raise ValueError("Addr is not initialized")
        if addr.file_type in _BLOCK_FILE_FILETYPE:
            block_header, stream = self._get_block_file(addr.file_selector)
            stream.seek(BlockFileHeader._BLOCK_HEADER_SIZE + (block_header.entry_size * addr.block_number))
            return io.BytesIO(stream.read(block_header.entry_size * addr.contiguous_blocks))
        elif addr.file_type == FileType.EXTERNAL:
            return (self._in_dir / f"f_{addr.external_file_number:06x}").open("rb")

        raise ValueError("unexpected file type")

    def get_data_for_addr(self, addr: Addr) -> typing.Optional[bytes]:
        if not addr.is_initialized:
            raise ValueError("Addr is not initialized")
        if addr.file_type in _BLOCK_FILE_FILETYPE:
            block_header, stream = self._get_block_file(addr.file_selector)
            stream.seek(BlockFileHeader._BLOCK_HEADER_SIZE + (block_header.entry_size * addr.block_number))
            return stream.read(block_header.entry_size * addr.contiguous_blocks)
        elif addr.file_type == FileType.EXTERNAL:
            external_file_path = self._in_dir / f"f_{addr.external_file_number:06x}"
            if not external_file_path.exists():
                return None
            with external_file_path.open("rb") as f:
                return f.read()

        raise ValueError("unexpected file type")

    def get_data_buffer(self, key: typing.Union[str, EntryStore, CacheKey], stream_number: int) -> typing.Optional[bytes]:
        if stream_number < 0 or stream_number > 2:
            raise ValueError("invalid stream number")
        if isinstance(key, EntryStore):
            es = key
        elif isinstance(key, CacheKey):
            es = self._keys[key.raw_key]
        else:
            es = self._keys[key]

        addr = es.data_addrs[stream_number]
        if not addr.is_initialized:
            return None

        data = self.get_data_for_addr(addr)
        if data is None:
            return None

        stream_length = es.data_sizes[stream_number]
        if data is not None and len(data) < stream_length:
            raise ValueError(f"Could not get all of the data for stream {stream_number}")
        data = data[0:stream_length]
        return data

    def get_metadata(self, key: typing.Union[str, EntryStore, CacheKey]) -> list[typing.Optional[CachedMetadata]]:
        buffer = self.get_data_buffer(key, 0)
        if not buffer:
            return [None]
        meta = CachedMetadata.from_buffer(buffer)
        return [meta]

    def get_cachefile(self, key: typing.Union[str, EntryStore, CacheKey]) -> list[bytes]:
        return [self.get_data_buffer(key, 1)]

    def __enter__(self) -> "ChromiumBlockFileCache":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def keys(self) -> typing.Iterable[str]:
        yield from self._keys.keys()

    def cache_keys(self) -> typing.Iterable[CacheKey]:
        for k in self._keys.keys():
            yield CacheKey(k)

    def values(self) -> typing.Iterable[EntryStore]:
        yield from self._keys.values()

    def items(self) -> typing.Iterable[tuple[str, EntryStore]]:
        yield from self._keys.items()

    def __contains__(self, item) -> bool:
        if isinstance(item, CacheKey):
            item = item.raw_key
        return item in self._keys

    def __getitem__(self, item) -> EntryStore:
        if isinstance(item, CacheKey):
            item = item.raw_key
        return self._keys[item]

    def close(self):
        for _, stream in self._block_files.values():
            stream.close()


@dataclasses.dataclass(frozen=True)
class SimpleCacheEOF:
    flags: int
    data_crc: int
    stream_size: int

    _SIMPLE_FINAL_MAGIC: typing.ClassVar[int] = 0xf4fa6f45970d41d8

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        magic = reader.read_uint64()
        if magic != SimpleCacheEOF._SIMPLE_FINAL_MAGIC:
            raise ValueError(f"Invalid magic (expected {SimpleCacheEOF._SIMPLE_FINAL_MAGIC}; got {magic}")

        flags = reader.read_uint32()
        data_crc = reader.read_uint32()
        stream_size = reader.read_uint32()

        return cls(flags, data_crc, stream_size)

    @property
    def has_crc(self):
        return self.flags & 1 > 0

    @property
    def has_key_sha256(self):
        return self.flags & 2 > 0


@dataclasses.dataclass(frozen=True)
class SimpleCacheHeader:
    version: int
    key_length: int
    key_hash: int

    _SIMPLE_INITIAL_MAGIC: typing.ClassVar[int] = 0xfcfb6d1ba7725c30

    @classmethod
    def from_reader(cls, reader: BinaryReader):
        magic = reader.read_uint64()
        if magic != SimpleCacheHeader._SIMPLE_INITIAL_MAGIC:
            raise ValueError(f"Invalid magic (expected {SimpleCacheHeader._SIMPLE_INITIAL_MAGIC}; got {magic}")
        version = reader.read_uint32()
        key_length = reader.read_uint32()
        key_hash = reader.read_uint32()

        if EIGHT_BYTE_PICKLE_ALIGNMENT:
            _ = reader.read_uint32()

        return cls(version, key_length, key_hash)


class SimpleCacheFile:
    def __init__(self, cache_file: typing.Union[os.PathLike, str]):
        self._path = pathlib.Path(cache_file)
        self._reader = BinaryReader(self._path.open("rb"))
        self._header = SimpleCacheHeader.from_reader(self._reader)
        self._key = self._reader.read_raw(self._header.key_length).decode("latin-1")

        if self._reader.is_eof:
            self._stream_0_eof = None
            self._stream_1_eof = None
            self._stream_0_start_offset_negative = 0
            self._stream_1_start_offset = 0
            self._stream_1_length = 0

            self._has_data = False
            return
        else:
            self._has_data = True

        self._reader.seek(-SIMPLE_EOF_SIZE, os.SEEK_END)
        self._stream_0_eof = SimpleCacheEOF.from_reader(self._reader)
        self._stream_0_start_offset_negative = -SIMPLE_EOF_SIZE - self._stream_0_eof.stream_size
        if self._stream_0_eof.has_key_sha256:
            self._stream_0_start_offset_negative -= 32

        self._reader.seek(-SIMPLE_EOF_SIZE - SIMPLE_EOF_SIZE - self._stream_0_eof.stream_size, os.SEEK_END)
        if self._stream_0_eof.has_key_sha256:
            self._reader.seek(-32, os.SEEK_CUR)
        stream_1_end_offset = self._reader.tell()
        self._stream_1_eof = SimpleCacheEOF.from_reader(self._reader)
        self._stream_1_start_offset = SIMPLE_EOF_SIZE + self._header.key_length
        self._stream_1_length = stream_1_end_offset - self._stream_1_start_offset

    def __enter__(self) -> "SimpleCacheFile":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_stream_0(self):
        if self._has_data:
            self._reader.seek(self._stream_0_start_offset_negative, os.SEEK_END)
            return self._reader.read_raw(self._stream_0_eof.stream_size)
        return b""

    def get_stream_1(self):
        if self._has_data:
            self._reader.seek(self._stream_1_start_offset, os.SEEK_SET)
            return self._reader.read_raw(self._stream_1_length)
        return b""

    @property
    def data_start_offset(self):
        return self._stream_1_start_offset

    @property
    def metadata_start_offset_negative(self):
        return self._stream_0_start_offset_negative

    @property
    def path(self) -> pathlib.Path:
        return self._path

    @property
    def key(self) -> str:
        return self._key

    @property
    def key_hash(self) -> int:
        return self._header.key_hash

    def close(self):
        self._reader.close()


class ChromiumSimpleFileCache(ChromiumCache):
    _STREAM_0_1_FILENAME_PATTERN = re.compile(r"^[0-9a-f]{16}_0$")

    def __init__(self, cache_dir: typing.Union[os.PathLike, str]):
        self._cache_dir = pathlib.Path(cache_dir)
        self._file_lookup = types.MappingProxyType(self._build_keys())

    @property
    def cache_dir(self) -> pathlib.Path:
        return self._cache_dir

    def _build_keys(self) -> dict[str, list[pathlib.Path]]:
        lookup: dict[str, list[pathlib.Path]] = {}
        for cache_file in self._cache_dir.iterdir():
            if cache_file.is_file() and ChromiumSimpleFileCache._STREAM_0_1_FILENAME_PATTERN.match(cache_file.name):
                with SimpleCacheFile(cache_file) as cf:
                    lookup.setdefault(cf.key, [])
                    lookup[cf.key].append(cache_file)

        return lookup

    def get_location_for_metadata(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        result = []
        if isinstance(key, CacheKey):
            key = key.raw_key
        for file in self._file_lookup[key]:
            file_length = file.stat().st_size
            with SimpleCacheFile(file) as cf:
                offset = file_length + cf.metadata_start_offset_negative
            result.append(CacheFileLocation(file.name, offset))
        return result

    def get_location_for_cachefile(self, key: typing.Union[str, CacheKey]) -> list[CacheFileLocation]:
        result = []
        if isinstance(key, CacheKey):
            key = key.raw_key
        for file in self._file_lookup[key]:
            with SimpleCacheFile(file) as cf:
                offset = cf.data_start_offset
            result.append(CacheFileLocation(file.name, offset))
        return result

    def get_metadata(self, key: typing.Union[str, CacheKey]) -> list[typing.Optional[CachedMetadata]]:
        result = []
        if isinstance(key, CacheKey):
            key = key.raw_key
        for file in self._file_lookup[key]:
            with SimpleCacheFile(file) as cf:
                buffer = cf.get_stream_0()
                if buffer:
                    result.append(CachedMetadata.from_buffer(buffer))
                else:
                    result.append(None)
        return result

    def get_cachefile(self, key: typing.Union[str, CacheKey]) -> list[bytes]:
        result = []
        if isinstance(key, CacheKey):
            key = key.raw_key
        for file in self._file_lookup[key]:
            with SimpleCacheFile(file) as cf:
                result.append(cf.get_stream_1())
        return result

    def __enter__(self) -> "ChromiumCache":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def close(self):
        pass

    def keys(self) -> typing.Iterable[str]:
        yield from self._file_lookup.keys()

    def cache_keys(self) -> typing.Iterable[CacheKey]:
        for k in self._file_lookup.keys():
            yield CacheKey(k)

    def get_file_for_key(self, key: typing.Union[str, CacheKey]) -> list[str]:
        if isinstance(key, CacheKey):
            key = key.raw_key
        return [x.name for x in self._file_lookup[key]]


def guess_cache_class(
        cache_dir: typing.Optional[typing.Union[pathlib.Path, os.PathLike]]) \
        -> typing.Optional[typing.Type[typing.Union[ChromiumBlockFileCache, ChromiumSimpleFileCache]]]:
    cache_dir = pathlib.Path(cache_dir)
    data_files = {"data_0", "data_1", "data_2", "data_3"}

    for file in cache_dir.iterdir():
        if file.name == "index-dir":
            return ChromiumSimpleFileCache
        elif file.name in data_files:
            return ChromiumBlockFileCache
        elif re.match(r"f_[0-9a-f]{6}", file.name):
            return ChromiumBlockFileCache
        elif re.match(r"^[0-9a-f]{16}_0$", file.name):
            return ChromiumSimpleFileCache

    return None


def convert_cache(input_cache_dir: typing.Union[str, os.PathLike], output_dir: typing.Union[str, os.PathLike]):
    in_cache_dir = pathlib.Path(input_cache_dir)
    out_dir = pathlib.Path(output_dir)
    cache_out_dir = out_dir / "cache_files"

    if not in_cache_dir.is_dir():
        raise ValueError("Input directory is not a directory or does not exist")

    if out_dir.exists():
        raise ValueError("Output directory already exists")

    out_dir.mkdir()
    cache_out_dir.mkdir()

    default_row_headers = ["file_hash", "key", "request_time", "response_time", "date"]
    dynamic_row_headers = set()
    rows: list[dict] = []

    cache_type = guess_cache_class(in_cache_dir)
    if cache_type is None:
        raise ValueError("Could not detect Chrome cache type")

    with cache_type(in_cache_dir) as cache:
        for key in cache.keys():
            out_extension = ""
            content_encoding = ""
            row = {"key": key}
            rows.append(row)

            metas = cache.get_metadata(key)
            datas = cache.get_cachefile(key)

            if len(metas) != len(datas):
                raise ValueError("Metadata records count does not match data records count")

            for meta, data in zip(metas, datas):
                if meta is not None:
                    row["request_time"] = meta.request_time
                    row["response_time"] = meta.response_time
                    for attribute, value in meta.http_header_attributes:
                        dynamic_row_headers.add(attribute)
                        if attribute in row:
                            row[attribute] += f"; {value}"
                        else:
                            row[attribute] = value

                    if mime := meta.get_attribute("content-type"):
                        out_extension = mimetypes.guess_extension(mime[0]) or ""

                    content_encoding = (meta.get_attribute("content-encoding") or [""])[0]

                if data is not None:
                    if content_encoding.strip() == "gzip":
                        try:
                            data = gzip.decompress(data)
                        except (EOFError, gzip.BadGzipFile):
                            pass
                    elif content_encoding.strip() == "br":
                        try:
                            data = brotli.decompress(data)
                        except brotli.error:
                            pass
                    elif content_encoding.strip() == "deflate":
                        try:
                            data = zlib.decompress(data, -zlib.MAX_WBITS)
                        except zlib.error:
                            pass

                    h = hashlib.sha256()
                    h.update(data)
                    cache_file_hash = h.hexdigest()
                    row["file_hash"] = cache_file_hash
                    with (cache_out_dir / (cache_file_hash + out_extension)).open("wb") as out:
                        out.write(data)
                else:
                    row["file_hash"] = "<No cache file data>"

    csv_out_f = (out_dir / "cache_report.csv").open("wt", encoding="utf-8", newline="")
    csv_out_f.write("\ufeff")
    csv_out = csv.DictWriter(
        csv_out_f, fieldnames=default_row_headers + sorted(dynamic_row_headers), dialect=csv.excel,
        quoting=csv.QUOTE_ALL, quotechar="\"", escapechar="\\")
    csv_out.writeheader()
    for row in rows:
        csv_out.writerow(row)

    csv_out_f.close()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"USAGE: {pathlib.Path(sys.argv[0]).name} <cache input dir> <out dir>")
        exit(1)
    convert_cache(sys.argv[1], sys.argv[2])
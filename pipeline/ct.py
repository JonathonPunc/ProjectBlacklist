"""Read hostnames from Certificate Transparency logs.

Every publicly trusted TLS certificate is published in CT logs within minutes
of being issued, phishing sites' certificates included. We read the logs that
use the static "tiled" API (https://c2sp.org/static-ct-api): the log is served
as immutable, CDN-cached files of 256 entries each, made for monitors like us.

We keep a cursor per log on the dist branch and, on each run, read the full
tiles added since the last one. Partial tiles are left for the next run.

Where a log offers "names" tiles (Let's Encrypt's do: one JSON line per
certificate with just its hostnames), we read those: about 7 KB per tile
instead of 160 KB. The spec warns they aren't verified against the log's
Merkle tree, which is fine for us: we only use them to pick names to judge.
"""

from __future__ import annotations

import gzip
import json
import struct
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

TILE = 256
SAN_OID = b"\x06\x03\x55\x1d\x11"   # OID 2.5.29.17, subjectAltName


@dataclass(frozen=True)
class Log:
    name: str
    url: str          # monitoring prefix, no trailing slash


def tile_path(index: int) -> str:
    """Tile index -> path segment, e.g. 1234067 -> x001/x234/067."""
    s = str(index)
    s = "0" * (-len(s) % 3) + s
    parts = [s[i:i + 3] for i in range(0, len(s), 3)]
    return "/".join([f"x{p}" for p in parts[:-1]] + [parts[-1]])


def checkpoint_size(text: str) -> int:
    lines = text.splitlines()
    if len(lines) < 3 or not lines[1].isdigit():
        raise ValueError("not a CT checkpoint")
    return int(lines[1])


def _der_len(b: bytes, i: int) -> tuple[int, int]:
    """Length at b[i]; returns (length, index of the first content byte)."""
    first = b[i]
    if first < 0x80:
        return first, i + 1
    n = first & 0x7F
    if n == 0 or n > 4:
        raise ValueError("bad DER length")
    return int.from_bytes(b[i + 1:i + 1 + n], "big"), i + 1 + n


def san_names(der: bytes) -> list[str]:
    """dNSName entries of the subjectAltName extension in a certificate or TBS."""
    at = der.find(SAN_OID)
    if at < 0:
        return []
    try:
        i = at + len(SAN_OID)
        if der[i] == 0x01:                       # critical BOOLEAN
            _, j = _der_len(der, i + 1)
            i = j + 1
        if der[i] != 0x04:                       # OCTET STRING wrapping the value
            return []
        _, i = _der_len(der, i + 1)
        if der[i] != 0x30:                       # SEQUENCE OF GeneralName
            return []
        length, i = _der_len(der, i + 1)
        end = i + length
        out = []
        while i < end:
            tag = der[i]
            n, j = _der_len(der, i + 1)
            if tag == 0x82:                      # [2] dNSName
                out.append(der[j:j + n].decode("ascii", "replace"))
            i = j + n
        return out
    except (IndexError, ValueError):
        return []


def tile_entries(data: bytes) -> Iterator[tuple[int, list[str]]]:
    """(timestamp ms, SAN names) for each entry of a data tile."""
    i, n = 0, len(data)
    while i < n:
        ts, etype = struct.unpack_from(">QH", data, i)
        i += 10
        if etype == 0:                                   # x509_entry
            ln = int.from_bytes(data[i:i + 3], "big")
            der = data[i + 3:i + 3 + ln]
            i += 3 + ln
        elif etype == 1:                                 # precert_entry
            i += 32                                      # issuer key hash
            ln = int.from_bytes(data[i:i + 3], "big")
            der = data[i + 3:i + 3 + ln]                 # TBSCertificate
            i += 3 + ln
        else:
            raise ValueError(f"unknown CT entry type {etype}")
        ext = int.from_bytes(data[i:i + 2], "big")
        i += 2 + ext
        if etype == 1:                                   # the pre-certificate itself
            ln = int.from_bytes(data[i:i + 3], "big")
            i += 3 + ln
        chain = int.from_bytes(data[i:i + 2], "big")
        i += 2 + chain
        if i > n:
            raise ValueError("truncated CT tile")
        yield ts, san_names(der)


def _maybe_gunzip(b: bytes) -> bytes:
    return gzip.decompress(b) if b[:2] == b"\x1f\x8b" else b


def names_entries(data: bytes) -> Iterator[tuple[int, list[str]]]:
    """(timestamp ms, names) for each line of a names tile."""
    for line in data.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        names = row.get("DNS") or []
        if not names:
            cn = (row.get("Subject") or {}).get("CommonName")
            names = [cn] if cn else []
        yield int(row.get("Timestamp", 0)), [str(n) for n in names]


def read_names(log: Log, start: int, end: int, get: Callable[[str], bytes], *,
               names_tiles: bool = True, workers: int = 8) -> Iterator[tuple[int, list[str]]]:
    """Entries [start, end) of a log in whole tiles (start must be a tile
    boundary; a trailing partial tile is skipped). Yields (timestamp, names)."""
    kind = "names" if names_tiles else "data"
    parse = names_entries if names_tiles else tile_entries
    urls = [f"{log.url}/tile/{kind}/{tile_path(t)}" for t in range(start // TILE, end // TILE)]
    with ThreadPoolExecutor(workers) as pool:
        for data in pool.map(lambda u: _maybe_gunzip(get(u)), urls):
            yield from parse(data)

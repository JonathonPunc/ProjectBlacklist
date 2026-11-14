"""Polite HTTP fetching, and cached reference data (PSL, Tranco).

Reference data is used to build the lists but never published, so it lives in
a private cache (the GitHub Actions cache in CI), not on the dist branch.
"""

from __future__ import annotations

import datetime as dt
import gzip
import http.client
import io
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

USER_AGENT = "ProjectBlacklist/0.1 (+https://github.com/JonathonPunc/ProjectBlacklist)"
MAX_BYTES = 256 * 1024 * 1024

Getter = Callable[[str], bytes]


class FetchError(Exception):
    pass


def http_get(url: str, *, timeout: float = 45, retries: int = 2) -> bytes:
    """GET a URL with our User-Agent. Retries network errors and 5xx, not 4xx."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"})
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise FetchError(f"{url}: larger than {MAX_BYTES} bytes")
                if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                        data = gz.read(MAX_BYTES + 1)
                    if len(data) > MAX_BYTES:
                        raise FetchError(f"{url}: decompresses past {MAX_BYTES} bytes")
                return data
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                raise FetchError(f"{url}: HTTP {exc.code}") from exc
            last = exc
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as exc:
            last = exc
        if attempt < retries:
            time.sleep(3 * (attempt + 1))
    raise FetchError(f"{url}: {last}")


def cached(url: str, path: Path, *, max_age: dt.timedelta, now: dt.datetime, get: Getter,
           fallback_age: dt.timedelta = dt.timedelta(days=7)) -> tuple[bytes, str]:
    """Return (data, how) for reference data, refreshing it when older than max_age.

    If a refresh fails, a cached copy up to fallback_age old is used instead.
    """
    age = None
    if path.is_file():
        age = now - dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
        if age <= max_age:
            return path.read_bytes(), "cached"
    try:
        data = get(url)
    except FetchError as exc:
        if age is not None and age <= fallback_age:
            return path.read_bytes(), f"stale cache ({age.days}d old) after: {exc}"
        raise
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
    return data, "downloaded"

"""Owner-only API credential file and redirect-rejecting HTTP handler."""
import os
from pathlib import Path
import re
import stat
import urllib.request

from portable_identity import DetectorError

_CREDENTIAL_PATH = Path(__file__).absolute().with_name(".granola-api-key")
_CREDENTIAL = re.compile(r"grn_[A-Za-z0-9_-]{1,4092}\Z")
_MAX_CREDENTIAL_BYTES = 4096


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DetectorError("API redirect rejected")


def file_credential(*, path=None):
    target = Path(path) if path is not None else _CREDENTIAL_PATH
    try:
        if not target.is_absolute() or "\x00" in str(target):
            raise ValueError()
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077):
                raise ValueError()
            chunks = []
            remaining = _MAX_CREDENTIAL_BYTES + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _MAX_CREDENTIAL_BYTES:
                raise ValueError()
        finally:
            os.close(fd)
        text = raw.decode("ascii")
        if text.endswith("\r\n"):
            text = text[:-2]
        elif text.endswith("\n"):
            text = text[:-1]
        if not _CREDENTIAL.fullmatch(text):
            raise ValueError()
        return text
    except Exception:
        raise DetectorError("Granola API credential unavailable") from None

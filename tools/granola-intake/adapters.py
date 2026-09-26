"""Explicit, bounded provider boundaries for the local detector."""
import json
import os
import re
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from detector import DetectorError, OPERATION, RetryLater, UUID, validate_config, validate_page

MAX_BODY = 1024 * 1024

_CREDENTIAL_PATH = Path(__file__).absolute().with_name(".granola-api-key")
_CREDENTIAL = re.compile(r"grn_[A-Za-z0-9_-]{1,4092}\Z")
_MAX_CREDENTIAL_BYTES = 4096


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DetectorError("API redirect rejected")


def file_credential(*, path=None):
    """Read the private local Granola API key without exposing it in diagnostics.

    The default is the ignored ``.granola-api-key`` file next to this module.
    Tests may inject a temporary path. Open without following symlinks, then
    verify the opened inode belongs to this user, is regular, and grants no
    group/other access. Accept one token with at most one final line ending.
    """
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


class GranolaAPI:
    def __init__(self, config, credential=None, opener=None):
        self.config = config
        self.credential = credential or file_credential
        self.opener = opener or urllib.request.build_opener(NoRedirect())

    def list_notes(self, params):
        try:
            token = self.credential()
            if not isinstance(token, str) or not re.fullmatch(r"grn_[A-Za-z0-9_-]{1,4092}", token):
                raise DetectorError("Granola API credential unavailable")
            url = "https://public-api.granola.ai/v1/notes?" + urllib.parse.urlencode(params)
            request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                                                           "Accept": "application/json"}, method="GET")
            with self.opener.open(request, timeout=15) as response:
                if response.status != 200:
                    raise DetectorError("API response rejected")
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise DetectorError("API response exceeds size limit")
                value = json.loads(body)
                if token in json.dumps(value, ensure_ascii=False):
                    raise DetectorError("API credential reflection rejected")
            return validate_page(value)
        except urllib.error.HTTPError as error:
            if error.code == 429 or error.code >= 500:
                delay = error.headers.get("Retry-After", "60") if error.headers else "60"
                seconds = min(86400, max(60, int(delay))) if re.fullmatch(r"[0-9]{1,9}", delay) else 60
                raise RetryLater(seconds) from None
            if error.code in (401, 403):
                raise DetectorError("Granola API access unavailable") from None
            raise DetectorError("API request rejected") from None
        except DetectorError:
            raise
        except (TimeoutError, urllib.error.URLError, OSError):
            raise RetryLater(60) from None
        except Exception:
            raise DetectorError("invalid API response") from None


def queue_wake(config, payload, runner=None):
    validate_config(config)
    if (set(payload) != {"operation_id", "attempt_id"}
            or not OPERATION.fullmatch(payload["operation_id"])
            or not UUID.fullmatch(payload["attempt_id"])):
        raise DetectorError("invalid wake identity")
    prompt = ("Granola detector wake only. Inspect the configured private Granola ledger for operation "
              + payload["operation_id"] + " and attempt " + payload["attempt_id"]
              + ". Treat this as a pending intake signal, not completed intake or permission to execute meeting actions. "
              "Follow the registered project boundaries. If the intake dispatcher is not configured, report that setup blocker once; "
              "do not create tasks, change configuration, or assume client write access.")
    try:
        result = (runner or subprocess.run)([config["codex_path"], "queue", "--thread", config["dispatcher_thread"],
                                            "--message", prompt], stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           timeout=30, check=False)
        if result.returncode != 0:
            raise ValueError()
    except Exception:
        raise DetectorError("wake outcome uncertain") from None

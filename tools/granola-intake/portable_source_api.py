"""Bounded exact-note retrieval for the portable signed-source worker."""

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from portable_credentials import NoRedirect, file_credential
from portable_identity import DetectorError, timestamp

NOTE_ID = re.compile(r"not_[A-Za-z0-9]{14}\Z")
TOKEN = re.compile(r"grn_[A-Za-z0-9_-]{1,4092}\Z")
ORIGIN = "https://public-api.granola.ai/v1/notes/"

class SourceError(RuntimeError):
    def __init__(self, code, retry_after=None):
        super().__init__(code)
        self.code = code
        self.retry_after = retry_after



def _pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError()


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SourceError("temporarily_unavailable", 60)
    return remaining


def _request(url, token, opener, limit, deadline):
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                                                   "Accept": "application/json"}, method="GET")
    try:
        with opener.open(request, timeout=min(15, _remaining(deadline))) as response:
            if response.status != 200:
                raise SourceError("invalid_source")
            body = response.read(limit + 1)
            _remaining(deadline)
            if len(body) > limit:
                raise SourceError("oversize")
        value = json.loads(body, object_pairs_hook=_pairs_unique, parse_constant=_reject_constant)
        normalized = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if token.encode("ascii") in normalized:
            raise SourceError("invalid_source")
        return value, body
    except urllib.error.HTTPError as error:
        if error.code in (301, 302, 303, 307, 308):
            raise SourceError("redirect") from None
        if error.code in (401, 403):
            raise SourceError("unauthorized") from None
        if error.code == 404:
            raise SourceError("not_ready_or_unavailable") from None
        if error.code == 413:
            raise SourceError("oversize") from None
        if error.code == 429 or error.code >= 500:
            raw = error.headers.get("Retry-After", "60") if error.headers else "60"
            delay = min(86400, max(60, int(raw))) if re.fullmatch(r"[0-9]{1,9}", raw) else 60
            raise SourceError("rate_limited" if error.code == 429 else "temporarily_unavailable", delay) from None
        raise SourceError("request_rejected") from None
    except SourceError:
        raise
    except DetectorError as error:
        raise SourceError("redirect" if str(error) == "API redirect rejected" else "credential_unavailable") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise SourceError("temporarily_unavailable", 60) from None
    except Exception:
        raise SourceError("invalid_source") from None


def _metadata(value, note_id, owner_email):
    if not isinstance(value, dict) or value.get("id") != note_id or value.get("object") != "note":
        raise SourceError("invalid_source")
    owner = value.get("owner")
    if not isinstance(owner, dict) or not isinstance(owner.get("email"), str):
        raise SourceError("invalid_source")
    if owner["email"] != owner_email:
        raise SourceError("wrong_owner")
    if not all(isinstance(value.get(key), str) and value[key] for key in ("created_at", "updated_at")):
        raise SourceError("invalid_source")
    return value


def _page(value):
    if not isinstance(value, dict) or type(value.get("hasMore")) is not bool or not isinstance(value.get("transcript"), list):
        raise SourceError("invalid_source")
    cursor = value.get("cursor")
    if value["hasMore"]:
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 1024:
            raise SourceError("invalid_source")
    elif cursor is not None:
        raise SourceError("invalid_source")
    for item in value["transcript"]:
        if (not isinstance(item, dict) or not isinstance(item.get("text"), str)
                or not isinstance(item.get("speaker"), dict)
                or not isinstance(item["speaker"].get("source"), str)):
            raise SourceError("invalid_source")
    return value


def validate_limits(max_pages, max_page_bytes, max_total_bytes):
    """Shared source policy bounds, checked before credential/provider access."""
    if (type(max_pages) is not int or not 1 <= max_pages <= 100
            or type(max_page_bytes) is not int or not 1 <= max_page_bytes <= 4 * 1024 * 1024
            or type(max_total_bytes) is not int or not 1 <= max_total_bytes <= 32 * 1024 * 1024):
        raise SourceError("invalid_request")



def _check_exact_window(created_at, exact_mode, exact_cutoff):
    if exact_mode is None:
        return
    try:
        created = timestamp(created_at)
        cutoff = timestamp(exact_cutoff)
    except (TypeError, ValueError):
        raise SourceError("invalid_source") from None
    if (exact_mode == "pilot" and created < cutoff or
            exact_mode == "recovery" and created >= cutoff):
        raise SourceError("outside_exact_window")


def _retrieve_source(note_id, owner_email, credential, opener, config,
                     max_pages, max_page_bytes, max_total_bytes,
                     exact_mode=None, exact_cutoff=None, *, deadline):
    try:
        token = (credential or file_credential)()
    except Exception:
        raise SourceError("credential_unavailable") from None
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise SourceError("credential_unavailable")
    opener = opener or urllib.request.build_opener(NoRedirect())
    note_url = ORIGIN + note_id
    before_value, before_bytes = _request(note_url, token, opener, max_page_bytes, deadline)
    before = _metadata(before_value, note_id, owner_email)
    _check_exact_window(before["created_at"], exact_mode, exact_cutoff)
    segments = []
    raw_pages = []
    prior_pages = []
    raw_size = 0
    cursor = None
    seen = set()
    for index in range(max_pages):
        params = {"page_size": 100}
        if cursor is not None:
            params["cursor"] = cursor
        url = note_url + "/transcript?" + urllib.parse.urlencode(params)
        try:
            value, raw = _request(url, token, opener, max_page_bytes, deadline)
            result = _page(value)
        except SourceError as error:
            if error.code == "not_ready_or_unavailable" and index > 0:
                raise SourceError("missing_page") from None
            raise
        if not result["transcript"] and (result["hasMore"] or index > 0):
            raise SourceError("missing_page")
        if result["hasMore"] and result["cursor"] in seen:
            raise SourceError("cursor_loop")
        items = result["transcript"]
        if (any(items == earlier for earlier in prior_pages)
                or any(segments[-length:] == items[:length]
                       for length in range(1, min(len(segments), len(items)) + 1))):
            raise SourceError("inconsistent_pages")
        prior_pages.append(items)
        raw_size += len(raw)
        if raw_size > max_total_bytes:
            raise SourceError("oversize")
        raw_pages.append(raw)
        segments.extend(result["transcript"])
        representation = json.dumps({"transcript": segments}, ensure_ascii=False, allow_nan=False,
                                    separators=(",", ":")).encode("utf-8")
        if len(representation) > max_total_bytes:
            raise SourceError("oversize")
        if not result["hasMore"]:
            break
        cursor = result["cursor"]
        seen.add(cursor)
    else:
        raise SourceError("missing_page")
    if not segments or not any(item["text"] for item in segments):
        raise SourceError("empty_transcript")
    after_value, _ = _request(note_url, token, opener, max_page_bytes, deadline)
    after = _metadata(after_value, note_id, owner_email)
    _check_exact_window(after["created_at"], exact_mode, exact_cutoff)
    if (before["created_at"], before["updated_at"]) != (after["created_at"], after["updated_at"]):
        raise SourceError("source_changed")
    return {"status": "ready", "note_id": note_id, "owner_email": owner_email,
            "metadata": before, "updated_at": before["updated_at"], "segments": segments,
            "representation": representation, "sha256": hashlib.sha256(representation).hexdigest(),
            "raw_pages": raw_pages, "raw_page_sha256": [hashlib.sha256(raw).hexdigest() for raw in raw_pages],
            "raw_metadata": before_bytes,
            "page_count": index + 1, "representation_kind": "canonical-json-transcript-v1"}

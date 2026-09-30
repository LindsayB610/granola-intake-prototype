"""Stable Granola note identity and strict timestamp parsing."""
import hashlib
from datetime import datetime, timezone
import re

NOTE_ID = re.compile(r"not_[A-Za-z0-9]{14}\Z")


class DetectorError(RuntimeError):
    """Sanitized source boundary error."""


def operation_id(note_id):
    return hashlib.sha256(("granola-initial-v1:" + note_id).encode()).hexdigest()


def timestamp(value):
    if (not isinstance(value, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})", value)):
        raise ValueError("invalid timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timezone required")
    return result.astimezone(timezone.utc)

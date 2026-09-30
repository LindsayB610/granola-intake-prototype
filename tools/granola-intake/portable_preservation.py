"""Atomic, collision-safe source bundles in a trusted workroom only."""

import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from portable_identity import operation_id as detector_operation_id
from portable_identity import NOTE_ID


class PreserveError(RuntimeError):
    """Content-free failure code; never include source or an OS error."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _markdown_transcript(segments):
    """Render source text in order without upgrading diarization to identity."""
    def visible(value):
        return (json.dumps(value, ensure_ascii=False).replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;").replace("`", "&#96;"))

    parts = ["# Granola transcript", "",
             "Speaker source and diarization labels are provider evidence, not verified identities.",
             f"Segments: {len(segments)}", ""]
    for index, item in enumerate(segments, 1):
        text = item["text"]
        speaker = item["speaker"]
        label = speaker.get("diarization_label")
        if label is not None and not isinstance(label, str):
            raise ValueError()
        fence = "`" * max(3, max((len(match.group()) for match in re.finditer(r"`+", text)), default=0) + 1)
        parts.extend([f"## Segment {index}", "",
                      "Speaker source (unverified): " + visible(speaker["source"]),
                      "Diarization label is unverified: " + visible(label),
                      f"Text UTF-8 SHA-256: {_digest(text.encode('utf-8'))}",
                      f"Text characters: {len(text)}", "", fence,
                      text, fence, ""])
    return ("\n".join(parts) + "\n").encode("utf-8")


def _source_files(source, operation_id, retrieved_at, *, markdown=False):
    try:
        note = source["note_id"]
        if (source["status"] != "ready" or not isinstance(note, str) or not NOTE_ID.fullmatch(note)
                or operation_id != detector_operation_id(note)
                or source["representation_kind"] != "canonical-json-transcript-v1"
                or not isinstance(source["owner_email"], str) or not source["owner_email"]
                or not isinstance(source["updated_at"], str) or not source["updated_at"]
                or not isinstance(retrieved_at, str)
                or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", retrieved_at)):
            raise ValueError()
        representation = source["representation"]
        metadata = source["raw_metadata"]
        pages = source["raw_pages"]
        hashes = source["raw_page_sha256"]
        if (not isinstance(representation, bytes) or not isinstance(metadata, bytes)
                or not isinstance(pages, list) or not 1 <= len(pages) <= 100
                or source["page_count"] != len(pages) or not isinstance(hashes, list)
                or len(hashes) != len(pages) or any(not isinstance(p, bytes) for p in pages)
                or sum(map(len, pages)) > 32 * 1024 * 1024
                or len(representation) > 32 * 1024 * 1024 or len(metadata) > 4 * 1024 * 1024
                or _digest(representation) != source["sha256"]
                or [_digest(p) for p in pages] != hashes):
            raise ValueError()
        parsed = json.loads(representation)
        meta = json.loads(metadata)
        parsed_pages = [json.loads(p) for p in pages]
        if (parsed != {"transcript": source["segments"]}
                or meta != source["metadata"] or meta.get("id") != note
                or meta.get("owner", {}).get("email") != source["owner_email"]
                or meta.get("updated_at") != source["updated_at"]
                or [item for page in parsed_pages for item in page["transcript"]] != source["segments"]):
            raise ValueError()
        segments = source["segments"]
        if (not isinstance(segments, list) or not segments
                or not any(item["text"] for item in segments)
                or any(not isinstance(item, dict) or not isinstance(item.get("text"), str)
                       or not isinstance(item.get("speaker"), dict)
                       or not isinstance(item["speaker"].get("source"), str)
                       for item in segments)):
            raise ValueError()
        for index, page in enumerate(parsed_pages):
            if (not isinstance(page, dict) or not isinstance(page.get("transcript"), list)
                    or type(page.get("hasMore")) is not bool
                    or page["hasMore"] != (index < len(parsed_pages) - 1)
                    or (page["hasMore"] and not isinstance(page.get("cursor"), str))
                    or (not page["hasMore"] and page.get("cursor") is not None)
                    or (not page["transcript"] and (index > 0 or page["hasMore"]))):
                raise ValueError()
        files = {"transcript.json": representation, "metadata.json": metadata}
        if markdown:
            files["transcript.md"] = _markdown_transcript(segments)
        files.update({f"page-{i:04d}.json": page for i, page in enumerate(pages, 1)})
        evidence = {"schema_version": 1, "operation_id": operation_id, "note_id": note,
                    "owner_email": source["owner_email"], "observed_version": source["updated_at"],
                    "representation_kind": source["representation_kind"],
                    "sha256": source["sha256"], "page_count": len(pages),
                    "file_sha256": {name: _digest(data) for name, data in files.items()}}
        if markdown:
            evidence["segment_count"] = len(segments)
        content_digest = _digest(_json_bytes(evidence))
        provenance = dict(evidence, retrieved_at=retrieved_at)
        files["provenance.json"] = _json_bytes(provenance)
        bundle = content_digest + "-" + _digest(files["provenance.json"])
        return note, content_digest, bundle, evidence, files
    except (KeyError, TypeError, ValueError, UnicodeError, AttributeError, OverflowError):
        raise PreserveError("invalid_source") from None


def _open_directory_chain(path):
    """Walk from / using no-follow directory descriptors, including workroom root."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(path).parts[1:]:
            if part in ("", ".", ".."):
                raise OSError()
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _child_dir(parent_fd, name, *, private=True):
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or info.st_mode & (0o077 if private else 0o022):
        os.close(fd)
        raise OSError()
    return fd


def _write_file(directory_fd, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _publish_exclusive(parent_fd, temporary, final):
    """macOS renameatx_np RENAME_EXCL; no replace of an existing bundle."""
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renameatx_np
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(temporary), parent_fd, os.fsencode(final), 0x4) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            return False
        raise OSError(error, "exclusive publish failed")
    os.fsync(parent_fd)
    return True


def _read_exact(directory_fd, name, expected_sha256, max_bytes):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or info.st_mode & 0o077
                or info.st_size > max_bytes):
            raise OSError()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(max_bytes + 1)
        if expected_sha256 is not None and _digest(data) != expected_sha256:
            raise OSError()
        return data
    finally:
        os.close(fd)


def _verify_bundle(parent_fd, bundle, evidence, files):
    content_digest = _digest(_json_bytes(evidence))
    if not re.fullmatch(re.escape(content_digest) + r"-[0-9a-f]{64}", bundle):
        raise OSError()
    fd = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise OSError()
        if set(os.listdir(fd)) != set(files):
            raise OSError()
        for name, data in files.items():
            if name == "provenance.json":
                saved = json.loads(_read_exact(fd, name, bundle[-64:], 1024 * 1024))
                timestamp = saved.pop("retrieved_at", None)
                if not isinstance(timestamp, str) or not re.fullmatch(
                        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", timestamp):
                    raise OSError()
                if saved != evidence:
                    raise OSError()
            else:
                _read_exact(fd, name, _digest(data), len(data))
    finally:
        os.close(fd)

def _cleanup_stage(parent_fd, stage):
    try:
        fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        for name in os.listdir(fd):
            os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(stage, dir_fd=parent_fd)


def _find_existing(parent_fd, content_digest, evidence, files):
    """Reuse any intact observation of these same source bytes and version."""
    prefix = content_digest + "-"
    matches = 0
    first = None
    with os.scandir(parent_fd) as entries:
        for entry in entries:
            if not entry.name.startswith(prefix):
                continue
            matches += 1
            if matches > 1000:
                raise PreserveError("existing_bundle_changed")
            try:
                _verify_bundle(parent_fd, entry.name, evidence, files)
            except (OSError, ValueError, TypeError, AttributeError):
                raise PreserveError("existing_bundle_changed") from None
            if first is None:
                first = entry.name
    return first


def preserve_source(source, root, *, operation_id, retrieved_at, markdown=False):
    """Write one complete private source bundle with exact-byte retry readback."""
    note, content_digest, bundle, evidence, files = _source_files(
        source, operation_id, retrieved_at, markdown=markdown)
    root = str(Path(root))
    if not Path(root).is_absolute() or ".." in Path(root).parts or os.path.realpath(root) != root:
        raise PreserveError("invalid_holding_root")
    stage = ".stage-" + uuid.uuid4().hex
    relative = f"transcripts/granola/{note}/{bundle}"
    fds = []
    stage_created = False
    try:
        fd = _open_directory_chain(root)
        fds.append(fd)
        for part in ("transcripts", "granola", note):
            fd = _child_dir(fd, part, private=part != "transcripts")
            fds.append(fd)
        parent_fd = fd
        fcntl.flock(parent_fd, fcntl.LOCK_EX)
        existing = _find_existing(parent_fd, content_digest, evidence, files)
        if existing is not None:
            bundle = existing
            relative = f"transcripts/granola/{note}/{bundle}"
            status = "reused"
        else:
            os.mkdir(stage, 0o700, dir_fd=parent_fd)
            stage_created = True
            stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=parent_fd)
            try:
                for name, data in files.items():
                    _write_file(stage_fd, name, data)
                os.fsync(stage_fd)
            finally:
                os.close(stage_fd)
            if not _publish_exclusive(parent_fd, stage, bundle):
                try:
                    _verify_bundle(parent_fd, bundle, evidence, files)
                except (OSError, ValueError, TypeError):
                    raise PreserveError("existing_bundle_changed") from None
                status = "reused"
            else:
                stage_created = False
                _verify_bundle(parent_fd, bundle, evidence, files)
                status = "saved"
        result = {"status": status, "operation_id": operation_id,
                "root": root, "relative_path": relative,
                "sha256": source["sha256"], "bundle_id": bundle,
                "source_evidence_sha256": content_digest,
                "provenance_sha256": bundle[-64:]}
        if markdown:
            result.update(markdown_relative_path=relative + "/transcript.md",
                          markdown_sha256=_digest(files["transcript.md"]))
        return result
    except PreserveError:
        raise
    except OSError:
        raise PreserveError("write_failed") from None
    except (ValueError, TypeError, AttributeError):
        raise PreserveError("existing_bundle_changed") from None
    finally:
        if stage_created and fds:
            try:
                _cleanup_stage(fds[-1], stage)
            except OSError:
                pass
        for fd in reversed(fds):
            os.close(fd)

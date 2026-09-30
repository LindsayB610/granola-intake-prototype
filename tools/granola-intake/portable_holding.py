"""Private held-source resolution for one signed-note operation."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

import portable_identity as identity
import portable_preservation as preservation


def _private_directory(path):
    """Portable owner-only root, outside this checkout and without symlinks."""
    target = Path(path)
    module_dir = Path(__file__).resolve().parent
    repo = (module_dir.parents[1] if module_dir.name == 'granola-intake'
            and module_dir.parent.name == 'tools' else module_dir)
    _need(target.is_absolute() and '..' not in target.parts and
          not any(part.is_symlink() for part in (target, *target.parents)) and
          target != repo and repo not in target.parents, 'invalid_holding_store')
    info = target.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
          not info.st_mode & 0o077, 'invalid_holding_store')
    return target


class HoldingError(RuntimeError):
    """Fixed code; never includes source or a private path."""


def _need(value, code='invalid_holding_store'):
    if not value:
        raise HoldingError(code)


class HoldingStore:
    def __init__(self, root):
        self.root = str(_private_directory(root))
        self.check()

    @classmethod
    def for_operation_resolution(cls, root):
        return cls(root)

    def check(self):
        _private_directory(self.root)
        _need(os.path.realpath(self.root) == self.root,
              'holding_bundle_changed')

    def resolve(self, operation, note_id, owner_email):
        """Recover one intact held bundle without provider or credential access."""
        self.check()
        _need(type(operation) is str and re.compile(r'[0-9a-f]{64}').fullmatch(operation)
              and type(note_id) is str and re.fullmatch(r'not_[A-Za-z0-9]{14}', note_id)
              and (owner_email is None or (type(owner_email) is str and owner_email))
              and identity.operation_id(note_id) == operation, 'invalid_holding_source')

        def directory(parent, name, *, shared=False):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            info = os.fstat(child)
            _need(info.st_uid == os.getuid() and not info.st_mode & (0o022 if shared else 0o077),
                  'holding_bundle_changed')
            return child

        def file_bytes(parent, name, limit):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                info = os.fstat(fd)
                _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                      and not info.st_mode & 0o077 and info.st_nlink == 1
                      and 0 < info.st_size <= limit, 'holding_bundle_changed')
                data = bytearray()
                while len(data) <= limit:
                    part = os.read(fd, min(65536, limit + 1 - len(data)))
                    if not part:
                        break
                    data.extend(part)
                _need(len(data) == info.st_size, 'holding_bundle_changed')
                return bytes(data)
            finally:
                os.close(fd)

        fds = []
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(fd)
            for index, part in enumerate(('transcripts', 'granola', note_id)):
                fd = directory(fd, part, shared=index == 0)
                fds.append(fd)
            names = [name for name in os.listdir(fd)
                     if re.fullmatch(r'[0-9a-f]{64}-[0-9a-f]{64}', name)]
            _need(len(names) == 1, 'holding_bundle_ambiguous')
            bundle = names[0]
            bundle_fd = directory(fd, bundle)
            fds.append(bundle_fd)
            provenance = file_bytes(bundle_fd, 'provenance.json', 1024 * 1024)
            _need(hashlib.sha256(provenance).hexdigest() == bundle[-64:],
                  'holding_bundle_changed')
            record = json.loads(provenance)
            _need(type(record) is dict, 'holding_bundle_changed')
            evidence = dict(record)
            _need(type(evidence.pop('retrieved_at',None)) is str and
                  hashlib.sha256(preservation._json_bytes(evidence)).hexdigest() == bundle[:64],
                  'holding_bundle_changed')
            hashes = record.get('file_sha256')
            _need(record.get('operation_id') == operation and record.get('note_id') == note_id
                  and identity.operation_id(record.get('note_id')) == operation
                  and type(record.get('owner_email')) is str and record['owner_email']
                  and (owner_email is None or record.get('owner_email') == owner_email)
                  and type(record.get('sha256')) is str
                  and re.fullmatch(r'[0-9a-f]{64}',record['sha256'])
                  and type(hashes) is dict and type(hashes.get('transcript.md')) is str
                  and re.fullmatch(r'[0-9a-f]{64}', hashes['transcript.md'])
                  and set(os.listdir(bundle_fd)) == set(hashes) | {'provenance.json'},
                  'holding_bundle_changed')
            for name, digest in hashes.items():
                _need(type(name) is str and re.fullmatch(r'(?:transcript\.(?:md|json)|metadata\.json|page-[0-9]{4}\.json)', name)
                      and type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest),
                      'holding_bundle_changed')
                raw = file_bytes(bundle_fd, name, 32 * 1024 * 1024)
                _need(hashlib.sha256(raw).hexdigest() == digest, 'holding_bundle_changed')
            relative = f'transcripts/granola/{note_id}/{bundle}'
            return {'operation_id':operation,'source_sha256':record['sha256'],
                    'source_evidence_sha256':bundle[:64],
                    'relative_path':relative,
                    'markdown_relative_path':relative + '/transcript.md',
                    'markdown_sha256':hashes['transcript.md'],
                    'holding_root':self.root}
        except (OSError, ValueError, KeyError, TypeError):
            raise HoldingError('holding_bundle_changed') from None
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def resolve_operation(self, operation, owner_email=None):
        """Resolve an operation to its sole verified private artifact bundle."""
        self.check()
        _need(type(operation) is str and re.compile(r'[0-9a-f]{64}').fullmatch(operation)
              and (owner_email is None or (type(owner_email) is str and owner_email)),
              'invalid_holding_source')
        fds = []
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(fd)
            for index, part in enumerate(('transcripts', 'granola')):
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=fd)
                info = os.fstat(fd)
                _need(info.st_uid == os.getuid() and
                      not info.st_mode & (0o022 if index == 0 else 0o077),
                      'holding_bundle_changed')
                fds.append(fd)
            matches = []
            for note_id in os.listdir(fd):
                if (re.fullmatch(r'not_[A-Za-z0-9]{14}', note_id) and
                        identity.operation_id(note_id) == operation):
                    matches.append(self.resolve(operation, note_id, owner_email))
            _need(len(matches) == 1, 'holding_bundle_missing' if not matches
                  else 'holding_bundle_ambiguous')
            return matches[0]
        except HoldingError:
            raise
        except (OSError, ValueError, KeyError, TypeError):
            raise HoldingError('holding_bundle_changed') from None
        finally:
            for fd in reversed(fds):
                os.close(fd)

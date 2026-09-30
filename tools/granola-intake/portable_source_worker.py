"""Isolated exact-note fetch for the portable receiver. No Codex access."""
import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import portable_credentials as adapters
import portable_source_api as source


def main():
    try:
        request = json.load(sys.stdin)
        item = source._retrieve_source(
            request['note_id'], request['owner_email'],
            lambda: adapters.file_credential(path=request['credential_path']), None, None,
            request['source_policy']['max_pages'],
            request['source_policy']['max_page_bytes'],
            request['source_policy']['max_total_bytes'],
            deadline=time.monotonic() + request['source_policy']['total_timeout'])
        for key in ('representation', 'raw_metadata'):
            item[key] = base64.b64encode(item[key]).decode('ascii')
        item['raw_pages'] = [base64.b64encode(page).decode('ascii') for page in item['raw_pages']]
        result = {'status': 'ready', 'item': item}
    except source.SourceError as error:
        result = {'status': 'error', 'code': error.code}
    except BaseException:
        result = {'status': 'error', 'code': 'invalid_source'}
    sys.stdout.write(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    main()

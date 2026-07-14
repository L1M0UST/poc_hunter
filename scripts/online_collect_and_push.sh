#!/usr/bin/env sh
set -eu

REMOTE="${POC_HUNTER_SFTP_REMOTE:-}"
if [ -z "$REMOTE" ]; then
  echo "POC_HUNTER_SFTP_REMOTE is required, for example user@host:/remote/inbox/"
  exit 2
fi

BUILD_OUTPUT="$(python main.py build-tasks)"
echo "$BUILD_OUTPUT"

ARCHIVE_PATH="$(printf '%s' "$BUILD_OUTPUT" | python -c "import json,sys; print((json.load(sys.stdin).get('archive_path') or ''))")"
TASKS_CREATED="$(printf '%s' "$BUILD_OUTPUT" | python -c "import json,sys; print(int(json.load(sys.stdin).get('tasks_created') or 0))")"

if [ "$TASKS_CREATED" -le 0 ] || [ -z "$ARCHIVE_PATH" ]; then
  exit 0
fi

REMOTE_TARGET="${REMOTE%/}/$(basename "$ARCHIVE_PATH")"
python main.py sftp-push "$ARCHIVE_PATH" "$REMOTE_TARGET"

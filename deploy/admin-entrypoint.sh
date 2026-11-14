#!/bin/bash
# Keep the backend and Nginx under the same container lifecycle.
set -u
umask 077
/usr/local/bin/admin &
admin_pid=$!
nginx -g 'daemon off;' &
nginx_pid=$!
stop() {
  kill -TERM "$admin_pid" "$nginx_pid" 2>/dev/null || true
  wait "$admin_pid" "$nginx_pid" 2>/dev/null || true
}
trap 'stop; exit 0' TERM INT
wait -n "$admin_pid" "$nginx_pid"
status=$?
# An unexpected clean exit also means this combined service is no longer healthy.
if [ "$status" -eq 0 ]; then status=1; fi
stop
exit "$status"

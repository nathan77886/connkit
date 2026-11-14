#!/bin/sh
# Launch only isolated, disposable fixtures, with loopback-only random ports.
set -eu
mysql_id=''
redis_id=''
cleanup() {
 if [ -n "$mysql_id" ]; then docker rm -f -v "$mysql_id" >/dev/null; fi
 if [ -n "$redis_id" ]; then docker rm -f -v "$redis_id" >/dev/null; fi
}
trap cleanup EXIT HUP INT TERM
mysql_id=$(docker run -d --label connkit.fixture=true -p 127.0.0.1::3306 -e MYSQL_ROOT_PASSWORD=connkit-disposable-fixture -e MYSQL_ROOT_HOST=% -e MYSQL_DATABASE=fixture mysql:8.0.42)
redis_id=$(docker run -d --label connkit.fixture=true -p 127.0.0.1::6379 redis:8.2.1 redis-server --save '' --appendonly no)
CONNKIT_FIXTURE_MYSQL=$(docker port "$mysql_id" 3306/tcp)
CONNKIT_FIXTURE_REDIS=$(docker port "$redis_id" 6379/tcp)
export CONNKIT_FIXTURE_MYSQL CONNKIT_FIXTURE_REDIS
go test -race -count=1 -timeout=120s -run TestNativeMySQLAndRedisFixtures -v ./internal/operations

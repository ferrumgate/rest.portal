#!/bin/bash
set +e
docker stop redis
set -e
docker run --net=host --name redis --rm -d redis

docker stop redis2
set -e
docker run --name redis2 --rm -d -p 6600:6379 redis

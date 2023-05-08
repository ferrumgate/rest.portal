#!/bin/bash
set +e
docker stop redis
set -e
docker run --net=host --name redis --rm -d redis

set +e
docker stop pebble
set -e
docker run --net=host --name pebble -e "PEBBLE_VA_NOSLEEP=1" letsencrypt/pebble

#set +e
#docker stop redisstack
#set -e
#docker run --name redisstack --rm -d -p 6380:6379 redis/redis-stack-server

#set +e
#docker stop redisgears
#set -e
#docker run --name redisgears --rm -d -p 6381:6379 redislabs/redisgears:latest

set +e
#docker stop es
set -e
#docker run --name es --rm -d -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" elasticsearch:8.5.0
###
##docker exec -ti $ES /bin/bash
## elasticsearch-reset-password -i -u elastic
## enter password 123456 for tests

#!/bin/bash
set +e
docker stop redis
set -e
docker run --net=host --name redis --rm -d redis

#set +e
#docker stop redis2
#set -e
#docker run --name redis2 --rm -d -p 6600:6379 redis

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

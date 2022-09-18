docker run - ti --network=host \
    -e PORT='9080' \
    -e REDIS_HOST='redis:6379' \
    -e BASE_RATE_LIMIT=10 \
    -v /tmp/ferrumgate:/etc/ferrumgate \
    -p 9080:9080 rest.portal

docker run -ti --network=host \
    -e PORT=8181 \
    -e REDIS_HOST="localhost:6379" \
    -e BASE_RATE_LIMIT=10 \
    -v /tmp/ferrumgate:/etc/ferrumgate \
    -p 8181:8181 rest.portal

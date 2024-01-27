#!/bin/bash
set +e
docker stop redis || true
docker rm redis || true
docker run --net=host --name redis --rm -d redis

docker stop pebble || true
docker rm pebble || true

echo '
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 8181,
    "tlsPort": 8443,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "domainBlocklist": ["blocked-domain.example"],
    "retryAfter": {
        "authz": 3,
        "order": 5
    }
  }
}
' >/tmp/my-pebble-config.json

docker run --net=host --name pebble -e "PEBBLE_VA_NOSLEEP=1" --mount src=/tmp/my-pebble-config.json,target=/test/my-pebble-config.json,type=bind --rm -d letsencrypt/pebble pebble -config /test/my-pebble-config.json

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

# run docker zimbra

mkdir -p /tmp/smtp4dev
echo '
{
    "ServerOptions": {
        "Port": 25,
        "AllowRemoteConnections": true,
        "Database": "database.db",
        "NumberOfMessagesToKeep": 100,
        "NumberOfSessionsToKeep": 100,
        "BasePath": "/",
        "TlsMode": "ImplicitTls",
        "TlsCertificate": "",
        "TlsCertificatePrivateKey": null,
        "HostName": "18563ad86c65",
        "ImapPort": 143,
        "RecreateDb": true
    },
    "RelayOptions": {
        "IsEnabled": false,
        "SmtpServer": "",
        "SmtpPort": 25,
        "TlsMode": 1,
        "AutomaticEmails": [],
        "SenderAddress": "",
        "Login": "",
        "Password": ""
    }
}
' >/tmp/smtp4dev/appsettings.json
docker stop smtp4dev || true
docker rm smtp4dev || true
docker run -d --rm --name smtp4dev -it -p 3000:80 -p 2525:25 -v /tmp/smtp4dev:/smtp4dev rnwood/smtp4dev

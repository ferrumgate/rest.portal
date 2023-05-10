# rest.portal

restfull service for management ui

## Getting started

To make it easy for you to get started with GitLab, here's a list of recommended next steps.

Already a pro? Just edit this README.md and make it your own. Want to make it easy?
[Use the template at the bottom](#editing-this-readme)!

### Test Active Directory

install `ldapsearch` using
> apt install ldap-utils

> ldapsearch -H ldap://192.168.88.254:389 \
> -x \
> -D cn=testad.local
> -w Qa1234567
> -b "ou=hamza"

ldapsearch -H ldap://192.168.88.254:389 -x -D "hamza" -w Qa1234567 -b "dc=testad,dc=local" "(sAMAccountName=hamza)"

### openssl pki tests

openssl s_client -connect localhost:8443 -showcerts

openssl x509 -text -in test.ca.cert |grep -E '(Subject|Issuer)'

### lets encrypt tests

 run pebble
docker run --net=host  -e "PEBBLE_VA_NOSLEEP=1" letsencrypt/pebble

certbot certonly --manual   --preferred-challenges http -d local.ferrumgate.com --agree-tos --manual-public-ip-logging-ok -m <support@ferrumgate.com>  --work-dir /tmp/acmework/ --logs-dir /tmp/acmelog --config-dir /tmp/acmeconf   --server <https://localhost:14000/dir> --no-verify-ssl

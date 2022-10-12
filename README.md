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

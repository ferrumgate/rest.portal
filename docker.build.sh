#!/bin/bash

set -e
npm run build
version=$(cat package.json | grep version | cut -d: -f2 | tr -d , | tr -d \" | tr -d " ")
docker build -t rest.portal .
docker tag rest.portal rest.portal:$version
echo "rest.portal:$version builded"
docker tag rest.portal registry.ferrumgate.zero/ferrumgate/rest.portal:$version
docker tag rest.portal registry.ferrumgate.zero/ferrumgate/rest.portal:latest
docker tag rest.portal ferrumgate/rest.portal:$version

while true; do
    read -p "do you want to push to local registry y/n " yn
    case $yn in
    [Yy]*)
        docker push registry.ferrumgate.zero/ferrumgate/rest.portal:$version
        docker push registry.ferrumgate.zero/ferrumgate/rest.portal:latest
        break
        ;;
    [Nn]*) exit ;;
    *) echo "please answer yes or no." ;;
    esac
done

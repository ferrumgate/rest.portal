#!/bin/bash

set -e
# copy web application output
#rm -rf build/web
#cp -R ../ui.portal/dist/portal build/web

first="$1"
second="$2"

npm run build

version=$(cat package.json | grep version | cut -d: -f2 | tr -d , | tr -d \" | tr -d " ")
docker build -t rest.portal .
docker tag rest.portal rest.portal:"$version"
echo "rest.portal:$version builded"
docker tag rest.portal registry.ferrumgate.zero/ferrumgate/rest.portal:"$version"
docker tag rest.portal registry.ferrumgate.zero/ferrumgate/rest.portal:latest
docker tag rest.portal ferrumgate/rest.portal:"$version"

execute() {
    docker push registry.ferrumgate.zero/ferrumgate/rest.portal:"$version"
    docker push registry.ferrumgate.zero/ferrumgate/rest.portal:latest
    if [ "$first" == "--push" ] || [ "$second" == "--push" ]; then
        docker push ferrumgate/rest.portal:"$version"
    fi

}

if [ "$first" == "--force" ] || [ "$second" == "--force" ]; then
    execute
    exit
else
    while true; do
        read -r -p "do you want push to local registry y/n " yn
        case $yn in
        [Yy]*)
            execute
            break
            ;;
        [Nn]*) exit ;;
        *) echo "please answer yes or no." ;;
        esac
    done
fi

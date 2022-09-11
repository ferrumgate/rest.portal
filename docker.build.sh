#!/bin/bash

set -e
npm run build
version=$(cat package.json | grep version | cut -d: -f2 | tr -d , | tr -d \" | tr -d " ")
docker build -t rest.portal .
docker tag rest.portal rest.portal:$version
echo "rest.portal:$version builded"
docker tag rest.portal registry.ferrumgate.local/ferrumgate/rest.portal:$version
docker tag rest.portal registry.ferrumgate.local/ferrumgate/rest.portal:latest

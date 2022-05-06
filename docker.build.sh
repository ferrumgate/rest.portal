

#!/bin/bash

set -e
npm run build
version=(cat package.json |grep version|cut -d: -f 2|tr -d \"|tr -d \)
docker build -t rest.portal .
docker tag rest.portal rest.portal:$version

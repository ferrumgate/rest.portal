

#!/bin/bash

set -e
npm run build
read -p 'versiyon numarası giriniz:  ' version
docker build -t rest.portal .

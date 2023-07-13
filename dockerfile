FROM node:18.13.0-bullseye-slim
RUN apt update &&\
    apt install --assume-yes --no-install-recommends openssl \
    ca-certificates gnupg certbot
#Create app directory
WORKDIR /usr/src/app
## copy web application dist
##ADD build/web /usr/src/app/webdocke
#RUN ls /usr/src/app/web
RUN sed -i 's/providers = provider_sect/#providers = provider_sect/g' /etc/ssl/openssl.cnf
RUN sed -i 's/^MinProtocol.*/MinProtocol = TLSv1/g' /etc/ssl/openssl.cnf
RUN sed -i 's/^CipherString.*/CipherString = DEFAULT:@SECLEVEL=1/g' /etc/ssl/openssl.cnf


# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package*.json /usr/src/app/

RUN npm install
# If you are building your code for production
# RUN npm ci --only=production

ADD build/src /usr/src/app/build/src
WORKDIR /usr/src/app
#RUN chown -R  node /usr/src/app
### delete sensitive test data
###RUN  start=$(grep -n 'start point for delete' build/src/service/configService.js |cut -d':' -f1); \
###    end=$(grep -n 'end point for delete' build/src/service/configService.js |cut -d':' -f1); \
###    sed -i "${start},${end}d" build/src/service/configService.js

RUN mkdir -p /var/lib/ferrumgate
RUN chown -R node:node /var/lib/ferrumgate
USER node
CMD ["npm","run","startdocker"]
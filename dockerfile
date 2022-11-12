FROM node:16.13.2-bullseye-slim
RUN apt update &&\
    apt install --assume-yes --no-install-recommends openssl \
    ca-certificates gnupg
#Create app directory
WORKDIR /usr/src/app


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
RUN  start=$(grep -n 'start point for delete' build/src/service/configService.js |cut -d':' -f1); \
    end=$(grep -n 'end point for delete' build/src/service/configService.js |cut -d':' -f1); \
    sed -i "${start},${end}d" build/src/service/configService.js


#USER node
CMD ["npm","run","startdocker"]
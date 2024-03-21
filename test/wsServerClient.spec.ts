import chai from 'chai';
import http from 'http';
import ws from 'ws';
import { ConfigService } from '../src/service/configService';
import { RateLimitService } from '../src/service/rateLimitService';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';
import { WebSocketClient } from '../src/ws/webSocketClient';
import { WebSocketServer } from '../src/ws/webSocketServer';

const expect = chai.expect;

describe('ws server client ', () => {

    beforeEach(async () => {

    })
    const configService = new ConfigService('nefnrclsr9lv', `/tmp/${Util.randomNumberString()}`);
    const redisService = new RedisService();
    const rateLimit = new RateLimitService(configService, redisService);

    it('create a server and connect and disconnect', (done) => {

        let connected = false;
        let wclient: any;
        const httpServer = http.createServer(function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.write('Hello World!');
            res.end();
        }).listen(3005);
        const server = new WebSocketServer(httpServer, rateLimit, (remoteAddress: string, socket: ws) => {
            return new WebSocketClient(remoteAddress, socket);
        });

        server.on('connection', async (client: WebSocketClient) => {
            connected = true;

            await server.close();
        });
        server.on('close', async (server: WebSocketServer) => {
            if (connected) {
                done();
                httpServer.close();
            }
        });

        wclient = new ws('ws://localhost:3005/', {
            origin: 'https://websocket.org'
        });

    }).timeout(120000);

    it('create a server and connect and disconnect2', (done) => {

        let connected = false;
        let wclient: any;
        const httpServer = http.createServer(function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.write('Hello World!');
            res.end();
        }).listen(3001);
        const server = new WebSocketServer(httpServer, rateLimit, (remoteAddress: string, socket: ws) => {
            return new WebSocketClient(remoteAddress, socket);
        });
        server.on('connection', async (client: WebSocketClient) => {
            connected = true;
            client.on('close', async (data: any) => {
                if (connected) {
                    await server.close();
                    httpServer.close();
                    done();

                }
            })
            await client.close();
        });

        wclient = new ws('ws://localhost:3001/', {
            origin: 'https://websocket.org'
        });

    }).timeout(10000);

    it('create a server and connect and disconnect with http', (done) => {

        let connected = false;
        let wclient: any;
        const httpServer = http.createServer(function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.write('Hello World!');
            res.end();
        }).listen(3002);
        const server = new WebSocketServer(httpServer, rateLimit, (remoteAddress: string, socket: ws) => {
            return new WebSocketClient(remoteAddress, socket);
        });
        server.on('connection', async (client: WebSocketClient) => {
            connected = true;
            client.on('close', async (data: any) => {
                if (connected) {
                    await server.close();
                    httpServer.close();
                    done();

                }
            })
            await client.close();
        });

        wclient = new ws('ws://localhost:3002/api/deneme', {
            origin: 'https://websocket.org'
        });

    }).timeout(10000);

    it('if client is not authenticated it is closed', (done) => {

        let connected = false;
        let wclient: any;
        const httpServer = http.createServer(function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.write('Hello World!');
            res.end();
        }).listen(3003);
        const server = new WebSocketServer(httpServer, rateLimit, (remoteAddress: string, socket: ws) => {
            return new WebSocketClient(remoteAddress, socket);
        });
        server.on('connection', async (client: WebSocketClient) => {
            connected = true;
            client.on('close', async (data: any) => {
                if (connected) {
                    await server.close();
                    httpServer.close();
                    done();

                }
            })

        });

        wclient = new ws('ws://localhost:3003/api/deneme', {
            origin: 'https://websocket.org'
        });

    }).timeout(75000);

})
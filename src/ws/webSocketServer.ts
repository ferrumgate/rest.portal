
import events from 'events';
import http from 'http';
import https from 'https';
import { logger } from '../common';
import url from 'url';
import { promisify } from 'util';
import ws from 'ws';
import { Util } from '../util';
import { WebSocketClient } from './webSocketClient';
import { Http2SecureServer } from 'http2';
import { RateLimitService } from '../service/rateLimitService';
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');


export type createClientFunc = (remoteAddress: string, socket: ws) => WebSocketClient;


export class WebSocketServer extends events.EventEmitter {


    protected httpServer: http.Server;

    protected websocket: ws.Server;
    protected clients: Map<string, WebSocketClient> = new Map();
    private checkTimer: any;
    constructor(httpServer: http.Server, protected rateLimit: RateLimitService,
        createClient: createClientFunc, pingInterval = 30000) {
        super();

        this.httpServer = httpServer;
        this.websocket = new ws.Server({
            noServer: true,

            perMessageDeflate: {
                zlibDeflateOptions: {
                    // See zlib defaults.
                    chunkSize: 1024,
                    memLevel: 7,
                    level: 3
                },
                zlibInflateOptions: {
                    chunkSize: 10 * 1024
                },
                // Other options settable:
                clientNoContextTakeover: true, // Defaults to negotiated value.
                serverNoContextTakeover: true, // Defaults to negotiated value.
                serverMaxWindowBits: 10, // Defaults to negotiated value.
                // Below options specified as default values.
                concurrencyLimit: 10, // Limits zlib concurrency for perf.
                threshold: 1024 // Size (in bytes) below which messages
                // should not be compressed.
            }
        });

        this.httpServer.on('upgrade', async (request, socket, head) => {

            logger.info(`upgrading url:${request.url}`);

            this.websocket.handleUpgrade(request, socket, head, (ws) => {
                this.websocket.emit('connection', ws, request);
            });

        });
        this.httpServer.on('error', (err) => {
            logger.error(err);
        })

        this.websocket.on('error', async (websocket: ws.Server, error: Error) => {
            logger.error(error);
        });




        this.websocket.on('connection', async (socket: ws, request: http.IncomingMessage) => {
            try {
                let remoteAddress = request.socket.remoteAddress?.toString() || 'unknown';
                logger.info(`client connected from ${remoteAddress}`);
                await this.rateLimit.check(remoteAddress, 'websocket', 100);
                await this.rateLimit.check(remoteAddress, 'websocketHourly', 10000);

                const client = createClient(remoteAddress, socket);
                this.clients.set(client.id, client);
                client.on(`close`, async (client: WebSocketClient) => {
                    this.clients.delete(client.id);

                });
                client.on('error', (error: any) => {
                    logger.error(error);
                });

                await this.onConnection(client);
            } catch (err) {
                logger.error(err);
                socket.close();
            }

        });

        this.checkTimer = setIntervalAsync(async () => {

            await this.checkClients();
        }, pingInterval);

        logger.info(`websocket is listening on ${JSON.stringify(this.httpServer.address())}`);

    }

    get connectedClients() {
        return this.clients;
    }

    async checkClients() {
        try {
            for (const client of this.clients) {

                if (!client[1].isAlive) {
                    await client[1].close();
                    continue;
                }
                client[1].isAlive = false;
                await client[1].ping();
            }
        } catch (ignored) {
            logger.error(ignored);
        }
    }


    async onConnection(client: WebSocketClient) {
        this.emit('connection', client);
    }


    async listen() {

    }
    async close() {
        for (const client of this.clients) {
            try {
                await client[1].close();
            } catch (ignored) {
                logger.error(ignored);
            }
        }

        try {
            await promisify(this.httpServer.close);

        } catch (ignored) {
            logger.error(ignored);
        }


        clearIntervalAsync(this.checkTimer);
        this.checkTimer = null;
        this.emit('close', this);
    }
}


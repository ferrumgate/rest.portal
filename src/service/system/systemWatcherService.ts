
import { Tunnel } from "../../model/tunnel";
import { logger } from "../../common";
import { RedisService, RedisServiceManuel } from "../redisService";
import Redis, { Cluster } from "ioredis";
import * as IORedis from 'ioredis';
import { EventEmitter, pipeline } from "stream";
import { HelperService } from "../helperService";
import { Util } from "../../util";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');



export class SystemWatcherService extends EventEmitter {
    redisSlave: RedisServiceManuel | null = null;
    redisSlaveFiller: RedisServiceManuel | null = null;
    tunnels: Map<string, Tunnel> = new Map();
    isFilling = false;
    waitList: Set<string> = new Set();
    waitListTimer: any | null = null;
    startTimer: any | null = null;
    isExecutingWaitList = false;
    isWorking = false;
    isStoping = false;
    constructor() {
        super();
        this.setMaxListeners(16);

    }
    createRedis() {

        return new RedisServiceManuel(process.env.REDIS_SLAVE_HOST || "localhost:6379", process.env.REDIS_SLAVE_PASS, 'single', async () => {
            await this.onRedisConnectionClosed();
        });
    }
    async createConnections() {
        this.redisSlave = this.createRedis();
        this.redisSlaveFiller = this.createRedis();
    }
    async start() {
        this.isStoping = false;
        this.startTimer = setIntervalAsync(async () => {
            if (!this.isWorking) {
                await this.startAgain();
            }
        }, 3000)
    }
    async stop() {
        this.isStoping = true;
        await clearIntervalAsync(this.startTimer);

    }
    async startAgain() {

        try {

            this.isWorking = true;
            this.isFilling = true;
            logger.info("starting watching");
            this.redisSlave = this.createRedis();
            this.redisSlaveFiller = this.createRedis();
            const cliendId = await this.redisSlave.cliendId();
            await this.redisSlave.trackBroadCast(cliendId, ['/tunnel/id/']);
            await this.redisSlave.onMessage((channel: string, msg: string) => {
                logger.debug("redis broadcast msg received");
                this.onMessage(channel, msg);

            });
            await this.redisSlave.subscribe('__redis__:invalidate');
            await this.startFirstFilling();
            //start checking
            this.waitListTimer = setIntervalAsync(async () => {
                try {
                    if (this.isStoping)
                        throw new Error('stoping watching')
                    await this.executeWaitList();
                } catch (err) {
                    logger.error(err);
                    await clearIntervalAsync(this.waitListTimer);
                    this.isWorking = false;
                    await this.reset();
                }
            }, 1000);

        } catch (err) {
            logger.error(err);
            this.isWorking = false;
            await this.reset();
        }

    }
    parseTunnel(tunnel: Tunnel) {
        tunnel.trackId = Util.convertToNumber(tunnel.trackId)
        tunnel.is2FA = Util.convertToBoolean(tunnel.is2FA);
        tunnel.isPAM = Util.convertToBoolean(tunnel.isPAM);

    }
    async startFirstFilling() {
        if (!this.redisSlaveFiller) return;
        let page = 0;
        let pos = '0';
        while (true && !this.isStoping) {
            logger.info(`getting tunnel page ${page}`);


            const [cursor, results] = await this.redisSlaveFiller.scan('/tunnel/id/*', pos, 10000, 'hash');
            pos = cursor;
            const pipeline = await this.redisSlaveFiller.multi();
            for (const key of results) {
                await pipeline.hgetAll(key) as Tunnel;
            }
            const tunnels = await pipeline.exec() as Tunnel[];
            const validTunnels = tunnels.filter(x => {
                this.parseTunnel(x);//important
                return HelperService.isValidTunnelNoException(x) ? false : true;
            })
            validTunnels.forEach(x => {
                if (x.id) {
                    this.tunnels.set(x.id, x);
                    this.emit('tunnelUpdated', x);
                    this.emit('tunnel', { tunnel: x, action: 'updated' })

                }
            });

            if (!cursor || cursor == '0')
                break;
            page++;
        }
        this.isFilling = false;

    }
    async executeWaitList() {
        if (!this.redisSlaveFiller) return;

        while (this.waitList.size && !this.isStoping) {
            logger.info(`system watcher executing wait list size ${this.waitList.size}`);
            let finalList = [];
            for (const item of this.waitList) {
                finalList.push(item);
                if (finalList.length >= 10000)
                    break;
            }

            logger.debug(`system watcher found wait list item ${finalList.length}`);
            const pipeline = await this.redisSlaveFiller.multi();
            finalList.forEach(async (x) => {
                await pipeline.hgetAll(x);
            });
            let results = await pipeline.exec() as Tunnel[];
            results = results.map(x => {
                //important all data comes from redis as string

                this.parseTunnel(x);
                return x;
            });

            for (let i = 0; i < finalList.length; ++i) {
                const keys = finalList[i].split('/').filter(y => y);
                if (keys.length >= 2) {
                    const tunnelKey = keys[2];
                    const tunnel = results[i];


                    const exception = HelperService.isValidTunnelNoException(tunnel);
                    if (exception) {
                        const ourTunnel = this.tunnels.get(tunnelKey);
                        if (ourTunnel) {//only tracked tunnels
                            this.emit('tunnelDeleted', ourTunnel);
                            this.emit('tunnel', { tunnel: ourTunnel, action: 'delete' })
                            this.tunnels.delete(tunnelKey);
                        }

                    } else {

                        this.tunnels.set(tunnelKey, tunnel);
                        this.emit('tunnelUpdated', tunnel);
                        this.emit('tunnel', { tunnel: tunnel, action: 'update' })

                    }

                }

                this.waitList.delete(finalList[i]);
            }

        }


    }
    async reset() {
        try {

            this.tunnels.clear();
            this.waitList.clear();
            this.emit('reset');
            this.emit('tunnel', { action: 'reset' })
            if (this.redisSlave)
                await this.redisSlave.disconnect();
            this.redisSlave = null;
            if (this.redisSlaveFiller)
                await this.redisSlaveFiller.disconnect();
            this.redisSlaveFiller = null;


        } catch (err) {
            logger.fatal(err);
        }
    }

    async onRedisConnectionClosed() {
        logger.error("redis connection closed");
        await this.reset();
    }

    async onMessage(channel: string, msg: string) {
        if (typeof msg == 'string' && msg && msg != 'null') {
            try {
                logger.debug(`system watcher message received ${msg}`);
                const filtered = msg.split(',').map(x => x.trim()).filter(y => y);
                filtered.forEach(x => this.waitList.add(x));

            } catch (err) {
                logger.error(err);
            }
        }
    }


}
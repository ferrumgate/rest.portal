
import { Tunnel } from "../../model/tunnel";
import { logger } from "../../common";
import { RedisService } from "../redisService";
import Redis, { Cluster } from "ioredis";
import * as IORedis from 'ioredis';
import { EventEmitter, pipeline } from "stream";
import { HelperService } from "../helperService";
import { Util } from "../../util";

export class RedisServiceManuel extends RedisService {
    /**
     *
     */
    isClosedManuel = false;
    constructor(protected host?: string, protected password: string | undefined = undefined, protected type: 'single' | 'cluster' | 'sentinel' = 'single', private onClose?: () => Promise<void>) {
        super(host, password, type);

        this.redis.on('close', async () => {
            if (this.onClose && !this.isClosedManuel)
                await this.onClose();
        })
    }
    override disconnect(): Promise<void> {
        this.isClosedManuel = true;
        return super.disconnect();
    }

    protected override createRedisClient(host?: string | undefined, password?: string | undefined, type?: "single" | "cluster" | "sentinel"): Redis | Cluster {

        let hosts: { host: string, port: number }[] = [];

        let parts = host?.split(',') || [];
        for (let i = 0; i < parts.length; ++i) {
            let splitted = parts[i].split(':');
            let redishost = splitted.length > 0 ? splitted[0] : 'localhost';
            let redisport = splitted.length > 1 ? Number(splitted[1]) : 6379
            hosts.push({ host: redishost, port: redisport });
        }
        if (!hosts.length) {
            hosts.push({ host: 'localhost', port: 6379 });
        }

        switch (type) {
            case 'single':
                let redis = new IORedis.default({
                    host: hosts[0].host,
                    port: hosts[0].port,
                    connectTimeout: 5000,
                    password: password,
                    lazyConnect: true,
                    maxRetriesPerRequest: null,
                    retryStrategy: (times) => {
                        return null;
                    },
                    autoResubscribe: false,
                    autoResendUnfulfilledCommands: false

                });
                return redis;


            default:
                throw new Error(`unknown redis type ${type}`);
        }

    }
}


export class TunnelWatcherService extends EventEmitter {
    redisSlave: RedisServiceManuel | null = null;
    redisSlaveFiller: RedisServiceManuel | null = null;
    tunnels: Map<string, Tunnel> = new Map();
    isFilling = false;
    waitList: Set<string> = new Set();
    waitListTimer: NodeJS.Timer | null = null;
    startTimer: NodeJS.Timer | null = null;
    isExecutingWaitList = false;
    constructor() {
        super();


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
    async startAgain() {

        try {
            this.isFilling = true;
            logger.info("starting watching");
            this.redisSlave = this.createRedis();
            this.redisSlaveFiller = this.createRedis();
            const cliendId = await this.redisSlave.cliendId();
            await this.redisSlave.trackBroadCast(cliendId, '/tunnel/id/');
            await this.redisSlave.onMessage((channel: string, msg: string) => {

                this.onMessage(channel, msg);

            });
            await this.redisSlave.subscribe('__redis__:invalidate');
            await this.startFilling();
            this.isFilling = false;
        } catch (err) {
            logger.error(err);
        }
    }
    parseTunnel(tunnel: Tunnel) {
        tunnel.trackId = Util.convertToNumber(tunnel.trackId)
        tunnel.is2FA = Util.convertToBoolean(tunnel.is2FA);
        tunnel.isPAM = Util.convertToBoolean(tunnel.isPAM);

    }
    async startFilling() {
        if (!this.redisSlaveFiller) return;
        let page = 0;
        let pos = '0';
        while (true) {
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
            });
            validTunnels.forEach(x => {
                if (x.id) {
                    this.tunnels.set(x.id, x);
                    this.emit('tunnelUpdated', x);
                }
            });

            if (!cursor || cursor == '0')
                break;
            page++;
        }
        this.waitListTimer = setInterval(async () => {
            this.executeWaitList();
        }, 1000);

    }
    async executeWaitList() {
        if (!this.redisSlaveFiller) return;
        try {
            if (this.isFilling)
                return;
            if (this.isExecutingWaitList) return;
            this.isExecutingWaitList = true;
            while (this.waitList.size) {
                logger.info(`executing wait list size ${this.waitList.size}`);
                let finalList = [];
                for (const item of this.waitList) {
                    finalList.push(item);
                    if (finalList.length >= 10000)
                        break;
                }

                logger.info(`found wait list item ${finalList.length}`);
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
                                this.tunnels.delete(tunnelKey);
                            }

                        } else {
                            this.tunnels.set(tunnelKey, tunnel);
                            this.emit('tunnelUpdated', tunnel);
                        }
                    }

                    this.waitList.delete(finalList[i]);
                }

            }
        } catch (err) {
            logger.error(err);
            //fatal error 
            await this.reset();

        }
        this.isExecutingWaitList = false;



    }
    async reset() {
        try {

            this.tunnels.clear();
            this.waitList.clear();
            if (this.waitListTimer)
                clearInterval(this.waitListTimer);
            this.waitListTimer = null;
            this.emit('reset');
            if (this.startTimer)
                clearTimeout(this.startTimer);
            if (this.redisSlave)
                await this.redisSlave.disconnect();
            this.redisSlave = null;
            if (this.redisSlaveFiller)
                await this.redisSlaveFiller.disconnect();
            this.redisSlaveFiller = null;
            this.startTimer = setTimeout(async () => {
                this.startAgain();
            }, 5000);

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
                const filtered = msg.split(',').map(x => x.trim()).filter(y => y);
                filtered.forEach(x => this.waitList.add(x));

            } catch (err) {
                logger.error(err);
            }
        }
    }


}
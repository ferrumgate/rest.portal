import { logger } from "../../common";
import { Util } from "../../util";
import { Gateway } from "../../model/network";
import { ConfigService } from "../configService";
import { RedisService } from "../redisService";
import { GatewayService } from "../gatewayService";
import NodeCache from "node-cache";
import { pipeline } from "stream";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export interface ConfigRequest {
    id: string;
    hostId: string;
    func: string,
    params: string[]
}

export interface ConfigResponse {
    id: string;
    isError: boolean;
    error?: string;
    result?: any;
}

export class ConfigPublicRoom {

    redisStreamKey: string;
    intervalWaitList: any = null;
    waitList: ConfigRequest[] = [];
    redis: RedisService;
    constructor(private gatewayId: string,
        private configService: ConfigService) {
        this.redisStreamKey = `/query/host/${gatewayId}`;
        this.redis = new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS);

    }
    async start() {
        this.lastTrimTime = new Date().getTime();
        this.intervalWaitList = setIntervalAsync(async () => {
            await this.processWaitList();
        }, 1000)
    }
    async stop() {
        this.waitList.splice(0);
        if (this.intervalWaitList)
            await clearIntervalAsync(this.intervalWaitList);
        this.intervalWaitList = null;
    }
    async getServiceNetworkByGatewayId(queryId: string, gatewayId?: string) {
        if (!gatewayId) {
            throw new Error(`getServiceNetworkByGatewayId gatewayId param is absent`);
        }
        const gateway = await this.configService.getGateway(gatewayId);
        if (!gateway)
            throw new Error('getServiceNetworkByGatewayId no gateway found');
        const network = await this.configService.getNetwork(gateway.networkId || '');
        if (!network)
            throw new Error('getServiceNetworkByGatewayId no network found');

        return {
            id: queryId,
            result: network.serviceNetwork
        } as ConfigResponse;

    }
    async executeRequest(item: ConfigRequest): Promise<ConfigResponse> {

        if (item.hostId != this.gatewayId) throw new Error(`execute query host id not equal`);
        logger.info(`execution query ${item.id}:${item.func}`);
        switch (item.func) {
            case 'getServiceNetworkByGatewayId':
                return await this.getServiceNetworkByGatewayId(item.id, ...item.params);

            default:
                throw new Error(`unknown execute command ${item.func}`);

        }
    }
    lastTrimTime = 0;
    trimTimeMS = 15 * 60 * 1000;
    async processWaitList() {
        try {
            if (this.waitList.length) {
                logger.info(`process waiting list count ${this.waitList.length}`);
            }
            if (this.lastTrimTime + this.trimTimeMS < new Date().getTime()) {
                logger.info(`trim stream ${this.redisStreamKey}`);
                await this.redis.expire(this.redisStreamKey, 60 * 60 * 1000);
                await this.redis.xtrim(this.redisStreamKey, (new Date().getTime() - this.trimTimeMS).toString());
            }
            while (this.waitList.length) {
                const items = this.waitList.slice(0, 10000);
                //process
                const pipeline = await this.redis.multi();
                for (const item of items) {
                    let response = null;
                    try {
                        response = await this.executeRequest(item);
                    } catch (err: any) {
                        logger.error(err);
                        response = {
                            id: item.id,
                            isError: true, error: err.message
                        }
                    }
                    try {
                        const json = JSON.stringify(response);
                        const b64 = Buffer.from(json).toString('base64');
                        await pipeline.xadd(this.redisStreamKey, { data: b64 });
                    } catch (err) {
                        logger.error(err);
                    }
                }

                await pipeline.exec();
                this.waitList.splice(0, 10000);
            }




        } catch (err) {
            logger.error(err);
        }
    }

    async push(query: ConfigRequest) {
        this.waitList.push(query);
    }
}


/**
 * class that receives job admin config requests and reply them
 */
export class ConfigPublicListener {

    /**
     *
     */
    intervalCheckRedis: any = null;
    intervalPublish: any = null;
    redisSlave: RedisService;
    isRedisMaster = false;
    roomList: Map<string, ConfigPublicRoom> = new Map();
    cache: NodeCache;
    constructor(private configService: ConfigService) {
        this.redisSlave = this.createRedis();
        this.cache = new NodeCache({ checkperiod: 600, deleteOnExpire: true, useClones: false, stdTTL: 600 });

        this.cache.on("expired", async (key, value: ConfigPublicRoom) => {
            await value.stop();
            this.roomList.delete(key);
        });

    }
    createRedis() {
        return new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS);
    }

    async start() {
        try {
            await this.checkRedisRole();
        } catch (err) { logger.error(err) };
        this.intervalCheckRedis = setIntervalAsync(async () => {
            await this.checkRedisRole();
        }, 15 * 1000);
    }
    async stop() {
        if (this.intervalCheckRedis)
            await clearIntervalAsync(this.intervalCheckRedis);
        this.intervalCheckRedis = null;
        if (this.intervalPublish)
            await clearIntervalAsync(this.intervalCheckRedis);
        this.intervalCheckRedis = null;
    }
    async checkRedisRole() {
        let previous = this.isRedisMaster;
        const info = await this.redisSlave.info();
        if (info.includes("role:master"))
            this.isRedisMaster = true;
        if (previous != this.isRedisMaster) {
            if (this.isRedisMaster) {
                await this.startListening();
            } else
                await this.stopListening();
        }
    }
    async startListening() {
        this.redisSlave = this.createRedis();
        this.redisSlave.onMessage(async (msg: string) => {
            await this.executeMessage(msg);
        })
    }
    async stopListening() {
        this.isRedisMaster = false;
        await this.redisSlave.disconnect();
    }

    async executeMessage(msg: string) {
        try {
            const query = JSON.parse(Buffer.from(msg, 'base64').toString()) as ConfigRequest;
            logger.info(`config query received from host:${query.hostId} func:${query.func}`)
            if (query.hostId) {
                let room = this.cache.get(query.hostId) as ConfigPublicRoom;
                if (!room) {
                    const roomNew = new ConfigPublicRoom(query.hostId, this.configService);
                    await this.roomList.set(query.hostId, roomNew);
                    await this.cache.set(query.hostId, roomNew);
                    room = roomNew;
                } else {
                    this.cache.ttl(query.hostId, 600);
                }
                await room.push(query);
            }

        } catch (err) {
            logger.error(err);
        }
    }


}
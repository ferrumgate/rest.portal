import { logger } from "../../common";
import { Util } from "../../util";
import { Gateway } from "../../model/network";
import { ConfigService } from "../configService";
import { RedisService } from "../redisService";
import { GatewayService } from "../gatewayService";
import NodeCache from "node-cache";
import { pipeline } from "stream";
import { timeStamp } from "console";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export interface ConfigRequest {
    id: string;
    gatewayId: string;
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
        this.redisStreamKey = `/query/gateway/${gatewayId}`;
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
            clearIntervalAsync(this.intervalWaitList);
        this.intervalWaitList = null;
    }
    async getGatewayById(queryId: string, gatewayId?: string) {
        logger.info(`config public executing command for ${gatewayId}: getGatewayById`)
        let result = {
            id: queryId
        } as ConfigResponse;

        if (!gatewayId) {
            return result;
        }
        const gateway = await this.configService.getGateway(gatewayId);
        if (!gateway)
            return result;

        result.result = gateway;
        return result;

    }
    async getNetworkByGatewayId(queryId: string, gatewayId?: string) {
        logger.info(`config public executing command for ${gatewayId}: getNetworkByGatewayId`)
        let result = {
            id: queryId
        } as ConfigResponse;

        if (!gatewayId) {
            return result;
        }
        const gateway = await this.configService.getGateway(gatewayId);
        if (!gateway)
            return result;
        const network = await this.configService.getNetwork(gateway.networkId || '');
        if (!network)
            return result;

        result.result = network;
        return result;

    }

    async getServicesByGatewayId(queryId: string, gatewayId?: string) {
        logger.info(`config public executing command for ${gatewayId}: getServices`)
        let result = {
            id: queryId,
            result: []
        } as ConfigResponse;

        if (!gatewayId) {
            return result;
        }
        const gateway = await this.configService.getGateway(gatewayId);
        if (!gateway)
            return result;
        const network = await this.configService.getNetwork(gateway.networkId || '');
        if (!network)
            return result;
        const services = await this.configService.getServicesByNetworkId(network.id);

        result.result = services;
        return result;

    }

    async getService(queryId: string, id?: string) {
        logger.info(`config public executing command for ${id}: getService`)
        let result = {
            id: queryId,
        } as ConfigResponse;

        const service = await this.configService.getService(id || '');
        if (!service)
            return result;
        result.result = service;
        return result;

    }


    async executeRequest(item: ConfigRequest): Promise<ConfigResponse> {

        if (item.gatewayId != this.gatewayId) throw new Error(`execute query gateway id not equal`);
        logger.info(`config public execution query ${item.id}:${item.func}`);
        switch (item.func) {
            case 'getGatewayById':
                return await this.getGatewayById(item.id, ...item.params);
            case 'getNetworkByGatewayId':
                return await this.getNetworkByGatewayId(item.id, ...item.params);
            case 'getServicesByGatewayId':
                return await this.getServicesByGatewayId(item.id, ...item.params);
            case 'getService':
                return await this.getService(item.id, ...item.params);

            default:
                throw new Error(`unknown execute command ${item.func}`);

        }
    }
    lastTrimTime = 0;
    trimTimeMS = 15 * 60 * 1000;
    async processWaitList() {
        try {
            if (this.waitList.length) {
                logger.info(`config public process public listening waiting list count ${this.waitList.length}`);
            }
            if (this.lastTrimTime + this.trimTimeMS < new Date().getTime()) {
                logger.info(`config public trim stream ${this.redisStreamKey}`);
                await this.redis.expire(this.redisStreamKey, 60 * 60 * 1000);
                await this.redis.xtrim(this.redisStreamKey, (new Date().getTime() - this.trimTimeMS).toString());
                this.lastTrimTime = new Date().getTime();
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
    redisSlave: RedisService | null = null;
    redisSlaveSub: RedisService | null = null;
    isRedisMaster = false;
    roomList: Map<string, ConfigPublicRoom> = new Map();
    cache: NodeCache;
    constructor(private configService: ConfigService) {

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
        await this.checkRedisRole();

        this.intervalCheckRedis = setIntervalAsync(async () => {

            await this.checkRedisRole();

        }, 15 * 1000);
    }
    async stop() {
        if (this.intervalCheckRedis)
            clearIntervalAsync(this.intervalCheckRedis);
        this.intervalCheckRedis = null;
        if (this.intervalPublish)
            clearIntervalAsync(this.intervalPublish);
        this.intervalPublish = null;

    }
    async checkRedisRole() {
        let previous = this.isRedisMaster;
        try {

            if (!this.redisSlave)
                this.redisSlave = this.createRedis();
            if (!this.redisSlaveSub)
                this.redisSlaveSub = this.createRedis();
            const info = await this.redisSlave.info();
            if (info.includes("role:master")) {
                this.isRedisMaster = true;
                logger.info("config public redis is master");
            } else {
                logger.info(`config public redis is slave`);
            }
            if (previous != this.isRedisMaster) {
                if (this.isRedisMaster) {
                    await this.startListening();
                } else
                    await this.stopListening();
            }
        } catch (err) {
            logger.error(err);
            this.isRedisMaster = previous;
            if (this.redisSlave)
                await this.redisSlave?.disconnect();
            this.redisSlave = null;
            if (this.redisSlaveSub)
                await this.redisSlaveSub?.disconnect();
            this.redisSlaveSub = null;
        }
    }
    async startListening() {
        logger.info('config public starting listener');
        if (this.redisSlaveSub) {
            this.redisSlaveSub.onMessage(async (channel: string, msg: string) => {
                await this.executeMessage(channel, msg);
            })
            await this.redisSlaveSub.subscribe(`/query/config`);
        }
    }
    async stopListening() {
        logger.info('config public stoping listener');
        this.isRedisMaster = false;
        if (this.redisSlaveSub)
            await this.redisSlaveSub.disconnect();
        this.redisSlaveSub = null;
    }

    async executeMessage(channel: string, msg: string) {
        try {

            const query = JSON.parse(Buffer.from(msg, 'base64').toString()) as ConfigRequest;
            logger.info(`config public config query received from gateway:${query.gatewayId} func:${query.func}`)
            if (query.gatewayId) {
                let room = this.cache.get(query.gatewayId) as ConfigPublicRoom;
                if (!room) {
                    const roomNew = new ConfigPublicRoom(query.gatewayId, this.configService);
                    await this.roomList.set(query.gatewayId, roomNew);
                    await this.cache.set(query.gatewayId, roomNew);
                    room = roomNew;
                    await room.start();
                } else {
                    this.cache.ttl(query.gatewayId, 600);
                }
                await room.push(query);
            }

        } catch (err) {
            logger.error(err);
        }
    }


}
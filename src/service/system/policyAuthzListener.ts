import NodeCache from "node-cache";
import { logger } from "../../common";
import { ConfigService } from "../configService";
import { RedisPipelineService, RedisService } from "../redisService";
import { TunnelService } from "../tunnelService";



//below are how commands work

// commandId/reset  
// commandId/update/clientId/isDrop/policyNumber/why/policyId
// commandId/delete/clientId


export class PolicyRoomService {
    serviceId: string = '';
    hostId: string = '';
    instanceId: string = '';
    interval: NodeJS.Timer;
    lastAlive: Date = new Date(1, 1, 1);

    redisStreamKey: string;
    commandId: number = 0;
    private redisGlobal: RedisService;
    private redisLocal: RedisService;
    private redisSlave: RedisService;


    constructor(private configService: ConfigService, private tunnelService: TunnelService, _hostId: string, _serviceId: string, _instanceId: string) {
        this.hostId = _hostId;
        this.serviceId = _serviceId;
        this.instanceId = _instanceId;
        this.redisGlobal = new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS);
        this.redisSlave = new RedisService(process.env.REDIS_SLAVE_HOST || "localhost:6379", process.env.REDIS_SLAVE_PASS);
        this.redisLocal = new RedisService(process.env.REDIS_LOCAL_HOST || "localhost:6379", process.env.REDIS_LOCAL_PASS);



        this.redisStreamKey = `/policy/service/${this.hostId}/${this.serviceId}/${this.instanceId}`;
        this.interval = setInterval(async () => {
            try {
                //we need to make things, continues ok
                this.commandId++;
                await this.redisLocal.xadd(this.redisStreamKey, { cmd: `${this.commandId}/ok` }), this.xaddId(this.commandId);

            } catch (err) { logger.error(err); }
        }, 5000);


    }
    xaddId(commandId: number) {
        return `${new Date().getTime()}-${commandId}`;
    }

    async start() {

    }
    async stop() {
        clearInterval(this.interval);
    }
    async sendReset() {
        this.commandId = 0;
        this.commandId++;
        await this.redisLocal.delete(this.redisStreamKey);
        await this.redisLocal.xadd(this.redisStreamKey, { cmd: `${this.commandId}/reset` }, this.xaddId(this.commandId));
    }
    async restart() {
        //reset everything and start again
        await this.sendReset();
        //calculate policy and send to client again
        // get auth and tunnel logs max;
        const lastpos = await this.redisLocal.xinfo(this.redisStreamKey);
        let pos = '';
        while (true) {
            const [cursor, items] = await this.redisLocal.scan('/tunnel/key/*', pos, 10000, 'hash');
            pos = cursor;
            if (items.length) {
                let pipeline = await this.redisLocal.multi();
                for (const tunnelkey of items) {
                    await pipeline.hgetAll(tunnelkey)
                }
                const tunnels = await pipeline.exec();

            }

            if (!pos || pos == '0')
                break;
        }



    }
}

export class PolicyAuthzListener {

    private redisLocalServiceListener: RedisService;

    private redisGlobal: RedisService;
    private cache: NodeCache;
    constructor(private configService: ConfigService, private tunnelService: TunnelService) {
        this.cache = new NodeCache({ checkperiod: 60, deleteOnExpire: true, useClones: false, stdTTL: 60 });
        this.redisGlobal = new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS);
        this.redisLocalServiceListener = new RedisService(process.env.REDIS_LOCAL_HOST || "localhost:6379", process.env.REDIS_LOCAL_PASS);
        this.start().catch(err => logger.error(err));
        this.cache.on("expired", async (key, value: PolicyRoomService) => {
            await value.stop();
        });
    }

    async connectToChanngel(hostId?: string, serviceId?: string, instanceId?: string) {
        if (!hostId || !serviceId || !instanceId) return;
        let key = `/${hostId}/${serviceId}/${instanceId}`;
        logger.info(`replicate to me ${key}`);

        let item = this.cache.get(key) as PolicyRoomService;
        if (item) {
            await item.restart();
        } else {
            const room = new PolicyRoomService(this.configService, this.tunnelService, hostId, serviceId, instanceId);
            this.cache.set(key, room);
            await room.restart();
        }



    }

    async iAmAliveMessage(hostId?: string, serviceId?: string, instanceId?: string) {
        if (!hostId || !serviceId || !instanceId) return;
        let key = `/${hostId}/${serviceId}/${instanceId}`;
        logger.info(`i am alive message from ${key}`);
        const item = this.cache.get(key) as PolicyRoomService;
        if (item) {//cache has this item, then set ttl again
            this.cache.ttl(key, 60);
        }
        //set to the global
        let serviceKey = `/service/${hostId}/${serviceId}/${instanceId}`;
        await this.redisGlobal.hset(serviceKey, {
            hostId: hostId, serviceId: serviceId, instanceId: instanceId, lastSeen: new Date().getTime()
        })
        await this.redisGlobal.expire(serviceKey, 5 * 60);

    }
    async onServiceMessage(channel: string, message: string) {
        try {
            const parts = message.split('/');
            if (!parts.length)
                return;
            if (parts[1] == 'alive') {//client sended alive
                await this.iAmAliveMessage(...parts.slice(1))
            }


            if (parts[1] == 'replicate') {
                await this.connectToChanngel(...parts.slice(1));
            }
        } catch (err) {
            logger.error(err);
        }
    }

    async start() {
        await this.redisLocalServiceListener.onMessage(this.onServiceMessage);
        await this.redisLocalServiceListener.subscribe(`/policy/service`);


    }


}
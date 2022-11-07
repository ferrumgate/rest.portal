import NodeCache from "node-cache";
import { Tunnel } from "../../model/tunnel";
import { logger } from "../../common";
import { ConfigService } from "../configService";
import { RedisPipelineService, RedisService } from "../redisService";
import { TunnelService } from "../tunnelService";
import { SystemWatcherService } from "./systemWatcherService";
import { PolicyService } from "../policyService";
import { rootCertificates } from "tls";
import { clearIntervalAsync, setIntervalAsync } from "set-interval-async";



//below are how commands work

// commandId/reset  
// commandId/update/clientId/isDrop/policyNumber/why/policyId
// commandId/delete/clientId


export class PolicyRoomService {
    serviceId: string = '';
    hostId: string = '';
    instanceId: string = '';
    private interval: any;


    private redisStreamKey: string;
    private commandId: number = 0;
    private redisGlobal: RedisService;
    private redisLocal: RedisService;
    private redisSlave: RedisService;
    //pipeline
    private redisLocalPipeline: RedisService;
    private pipelineInterval: any;
    private pipelineCommandCount = 0;

    constructor(private configService: ConfigService, private tunnelService: TunnelService, _hostId: string, _serviceId: string, _instanceId: string) {
        this.hostId = _hostId;
        this.serviceId = _serviceId;
        this.instanceId = _instanceId;
        this.redisGlobal = new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS);
        this.redisSlave = new RedisService(process.env.REDIS_SLAVE_HOST || "localhost:6379", process.env.REDIS_SLAVE_PASS);
        this.redisLocal = new RedisService(process.env.REDIS_LOCAL_HOST || "localhost:6379", process.env.REDIS_LOCAL_PASS);
        this.redisLocalPipeline = new RedisService(process.env.REDIS_LOCAL_HOST || "localhost:6379", process.env.REDIS_LOCAL_PASS);



        this.redisStreamKey = `/policy/service/${this.hostId}/${this.serviceId}/${this.instanceId}`;
        this.interval = setIntervalAsync(async () => {
            try {
                //we need to make things, continues ok
                this.commandId++;
                await this.redisLocal.xadd(this.redisStreamKey, { cmd: `${this.commandId}/ok` }), this.xaddId(this.commandId);

            } catch (err) { logger.error(err); }
        }, 5000);
        this.pipelineInterval = setIntervalAsync(async () => {
            if (this.pipelineCommandCount) {
                this.redisLocalPipeline.expire
                this.pipelineCommandCount = 0;
            }
        }, 1000);


    }
    xaddId(commandId: number) {
        return `${new Date().getTime()}-${commandId}`;
    }

    async start() {

    }
    async stop() {
        await clearIntervalAsync(this.interval);
    }
    async sendReset() {
        this.commandId = 0;
        this.commandId++;
        await this.redisLocal.delete(this.redisStreamKey);
        await this.redisLocal.xadd(this.redisStreamKey, { cmd: `${this.commandId}/reset` }, this.xaddId(this.commandId));
    }
    async sendUpdate(trackId: number, isDrop: number, policyNumber: number,
        policyId: string, why: number) {
        this.commandId++;
        await this.redisLocal.xadd(this.redisStreamKey, { cmd: `${this.commandId}/update/${trackId}/${isDrop}/${policyNumber}/${why}/${policyId}` }, this.xaddId(this.commandId));

    }
    async sendDelete(trackId: number) {
        await this.redisLocal.xadd(this.redisStreamKey, { cmd: `${this.commandId}/delete/${trackId}` }, this.xaddId(this.commandId));
    }
}

export class PolicyAuthzListener {

    private redisLocalServiceListener: RedisService;
    private redisGlobal: RedisService;
    private cache: NodeCache;
    private waitList: { tunnel?: Tunnel, action: string }[] = [];
    private waitListTimer: any | null = null;
    private waitListIsWorking = false;
    private roomList = new Map<string, PolicyRoomService>();
    private hostId = '';
    constructor(private configService: ConfigService, private policyService: PolicyService,
        private tunnelService: TunnelService, private systemWatcher: SystemWatcherService) {
        this.hostId = process.env.HOST_ID || '';
        this.cache = new NodeCache({ checkperiod: 60, deleteOnExpire: true, useClones: false, stdTTL: 60 });
        this.redisGlobal = new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS);
        this.redisLocalServiceListener = new RedisService(process.env.REDIS_LOCAL_HOST || "localhost:6379", process.env.REDIS_LOCAL_PASS);
        this.start().catch(err => logger.error(err));
        this.cache.on("expired", async (key, value: PolicyRoomService) => {
            await value.stop();
            this.roomList.delete(key);
        });
        this.startTunnelWatcher().catch(err => logger.error(err));


    }
    async startTunnelWatcher() {
        this.systemWatcher.on('tunnel', async (arg: { tunnel?: Tunnel, action: string }) => {
            this.waitList.push(arg);
        })

        if (this.waitListTimer)
            clearIntervalAsync(this.waitListTimer);
        this.waitListTimer = setIntervalAsync(async () => {
            await this.processWaitList();
        }, 2000);
    }
    async policyCalculate(item: { tunnel?: Tunnel, action: string }) {
        if (item.action == 'reset') {
            for (const room of this.roomList.values()) {
                await room.sendReset();
            }
        }
        else {
            const hostId = item.tunnel?.hostId;
            if (!hostId && this.hostId != hostId)//check if this tunnel belongs to this tunnel
                return;
            if (!item.tunnel?.trackId)
                return;

            for (const room of this.roomList.values()) {

                const presult = await this.policyService.authorize(item.tunnel.trackId, room.serviceId, false, item.tunnel);
                if (typeof presult == 'number') {//this means error, drop trackId

                } else {

                }

            }

        }

    }
    async processWaitList() {
        if (this.waitListIsWorking) return;
        this.waitListIsWorking = true;
        try {
            if (this.processWaitList.length) {
                logger.info(`process waiting list count ${this.processWaitList.length}`);
            }
            let page = 0;
            while (this.processWaitList.length) {
                logger.info(`process waiting list page ${page++}`);
                const items = this.waitList.slice(0, 10000);
                //process
                for (const item of items) {
                    if (item.action != 'reset') {

                    }
                    await this.policyCalculate(item);
                }

                this.waitList.splice(0, 10000);
            }

        } catch (err) {
            logger.fatal(err);
        }
        this.waitListIsWorking = false;
    }

    async replicate(hostId?: string, serviceId?: string, instanceId?: string) {
        if (!hostId || !serviceId || !instanceId) return;
        let key = `/${hostId}/${serviceId}/${instanceId}`;
        logger.info(`replicate to me ${key}`);

        let item = this.cache.get(key) as PolicyRoomService;
        if (item) {
            await item.sendReset();
        } else {
            const room = new PolicyRoomService(this.configService, this.tunnelService, hostId, serviceId, instanceId);
            this.cache.set(key, room);
            this.roomList.set(key, room);
            await room.sendReset();
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
                await this.replicate(...parts.slice(1));
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
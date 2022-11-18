import NodeCache from "node-cache";
import { Tunnel } from "../../model/tunnel";
import { logger } from "../../common";
import { ConfigService } from "../configService";
import { RedisPipelineService, RedisService } from "../redisService";
import { TunnelService } from "../tunnelService";
import { SystemWatcherService } from "./systemWatcherService";
import { PolicyAuthzResult, PolicyService } from "../policyService";
import { rootCertificates } from "tls";
import { channel } from "diagnostics_channel";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');
import fsp from 'fs/promises';
import { Util } from "../../util";


//below are how commands work

// commandId/reset  
// commandId/update/clientId/isDrop/policyNumber/why/policyId
// commandId/delete/clientId
interface PolicyRoomCommand {
    isOK?: boolean;
    isReset?: boolean;
    isDelete?: boolean;
    trackId?: number;
    policyResult?: PolicyAuthzResult;
}

export class PolicyRoomService {
    serviceId: string = '';
    gatewayId: string = '';
    instanceId: string = '';
    private interval: any;


    redisStreamKey: string;
    private commandId: number = 0;
    private redisLocal: RedisService;
    //pipeline

    private waitList: PolicyRoomCommand[] = [];
    private waitListInterval: any;
    public lastProcessSuccessfull: number = new Date().getTime();
    private trimStreamInterval: any;
    constructor(_gatewayId: string, _serviceId: string, _instanceId: string) {
        this.gatewayId = _gatewayId;
        this.serviceId = _serviceId;
        this.instanceId = _instanceId;

        this.redisLocal = new RedisService(process.env.REDIS_LOCAL_HOST || "localhost:6379", process.env.REDIS_LOCAL_PASS);
        this.redisStreamKey = `/policy/service/${this.gatewayId}/${this.serviceId}/${this.instanceId}`;

    }
    private xaddId(commandId: number) {
        return `${new Date().getTime()}-${commandId}`;
    }

    get commandList() {
        return this.waitList;
    }

    async start() {
        this.interval = setIntervalAsync(async () => {
            await this.pushOk();
        }, 5000);
        this.waitListInterval = setIntervalAsync(async () => {
            await this.processWaitList();
        }, 1000);
        //every day delete old records
        this.trimStreamInterval = setIntervalAsync(async () => {
            await this.trimStream();
        }, 24 * 60 * 60 * 1000);
    }
    async stop() {
        this.waitList.splice(0);
        if (this.interval)
            await clearIntervalAsync(this.interval);
        this.interval = null;
        if (this.waitListInterval)
            await clearIntervalAsync(this.waitListInterval);
        this.waitListInterval = null;
        if (this.trimStreamInterval)
            await clearIntervalAsync(this.trimStreamInterval);
        this.trimStreamInterval = null;
    }
    async trimStream() {
        try {
            logger.info(`policy room trimming stream ${this.redisStreamKey}`);
            let lastDay = new Date().getTime() - (24 * 60 * 60 * 1000);
            await this.redisLocal.xtrim(this.redisStreamKey, lastDay.toString());
        } catch (err) {
            logger.error(err);
        }
    }
    async pushOk() {
        logger.debug(`policy room: /${this.gatewayId}/${this.serviceId}/${this.instanceId} push ok`)
        this.waitList.push({ isOK: true })
    }
    async pushReset() {
        logger.debug(`policy room: /${this.gatewayId}/${this.serviceId}/${this.instanceId} push reset`)
        this.waitList.splice(0);
        this.waitList.push({ isReset: true })
    }
    async pushDelete(trackId: number) {
        logger.debug(`policy room: /${this.gatewayId}/${this.serviceId}/${this.instanceId} push delete`)
        this.waitList.push({ trackId: trackId, isDelete: true });
    }
    async push(trackId: number, result: PolicyAuthzResult) {
        logger.debug(`policy room: /${this.gatewayId}/${this.serviceId}/${this.instanceId} push`)
        this.waitList.push({ trackId: trackId, policyResult: result });
    }

    private async processWaitList() {
        let tmp = this.commandId;//store it
        try {
            let page = 0;
            logger.debug(`policy room: /${this.gatewayId}/${this.serviceId}/${this.instanceId} wait list: ${this.waitList.length}`)
            while (this.waitList.length) {
                logger.info(`policy room: executing wait list service on /${this.gatewayId}/${this.serviceId}/${this.instanceId} page:${page}`)
                let snapshot = this.waitList.slice(0, 10000);
                let pipeline = await this.redisLocal.multi();
                for (const cmd of snapshot) {
                    if (cmd.isReset) {
                        await pipeline.delete(this.redisStreamKey);
                        //await pipeline.xtrim(this.redisStreamKey, new Date().getTime().toString());
                        this.commandId = 0;
                        this.commandId++;
                        await pipeline.xadd(this.redisStreamKey, { cmd: `${this.commandId}/reset` }, this.xaddId(this.commandId));
                        logger.debug(`policy room: write push reset to service: /${this.gatewayId}/${this.serviceId}/${this.instanceId}`)
                    } else
                        if (cmd.isOK) {
                            this.commandId++;
                            await pipeline.xadd(this.redisStreamKey, { cmd: `${this.commandId}/ok` }, this.xaddId(this.commandId));
                            logger.debug(`policy room: write push ok to service: /${this.gatewayId}/${this.serviceId}/${this.instanceId}`)
                        }
                        else if (cmd.isDelete && cmd.trackId) {
                            this.commandId++;
                            await pipeline.xadd(this.redisStreamKey, { cmd: `${this.commandId}/delete/${cmd.trackId}` }, this.xaddId(this.commandId));
                            logger.debug(`policy room: write push delete to service: /${this.gatewayId}/${this.serviceId}/${this.instanceId}`)
                        }
                        else if (cmd.trackId && cmd.policyResult) {
                            this.commandId++;
                            let isDrop = cmd.policyResult.error ? 1 : 0;
                            await pipeline.xadd(this.redisStreamKey, { cmd: `${this.commandId}/update/${cmd.trackId}/${isDrop}/${cmd.policyResult.index || 0}/${cmd.policyResult.error + 10000}/${cmd.policyResult.rule?.id || 0}` }, this.xaddId(this.commandId));
                            logger.debug(`policy room: write push update to service: /${this.gatewayId}/${this.serviceId}/${this.instanceId}`)
                        }
                }
                await pipeline.exec();
                this.waitList.splice(0, 10000);
            }
            this.lastProcessSuccessfull = new Date().getTime();
        } catch (err) {
            logger.error(err);
            this.commandId = tmp;
        }
    }

}

class GatewayId {


    static async read(configFilePath: string) {

        const file = (await fsp.readFile(configFilePath)).toString();
        const hostline = file.split('\n').find(x => x.startsWith('gatewayId='));
        if (!hostline) throw new Error(`no gateway id found in config ${configFilePath}`);
        const parts = hostline.split('=');
        if (parts.length != 2) throw new Error(`no gateway id found in config ${configFilePath}`);
        let gatewayId = parts[1];
        if (!gatewayId)
            throw new Error(`no gateway id found in config ${configFilePath}`);
        return gatewayId;
    }
}

export class PolicyAuthzListener {

    private redisLocalServiceListener: RedisService;
    private redisGlobal: RedisService;
    private cache: NodeCache;
    private waitList: { tunnel?: Tunnel, action: string }[] = [];
    private waitListTimer: any | null = null;

    private roomList = new Map<string, PolicyRoomService>();
    private gatewayId = '';
    private isStarted = false;
    private configFile = '/etc/ferrumgate/config';
    constructor(private policyService: PolicyService,
        private systemWatcher: SystemWatcherService, configFile?: string) {
        this.gatewayId = process.env.GATEWAY_ID || '';
        this.cache = new NodeCache({ checkperiod: 60, deleteOnExpire: true, useClones: false, stdTTL: 60 });
        this.redisGlobal = new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS);
        this.redisLocalServiceListener = new RedisService(process.env.REDIS_LOCAL_HOST || "localhost:6379", process.env.REDIS_LOCAL_PASS);

        this.cache.on("expired", async (key, value: PolicyRoomService) => {
            await value.stop();
            this.roomList.delete(key);
        });
        if (configFile) {
            this.configFile = configFile;
        }

    }
    async setGatewayId(gatewayId: string) {
        this.gatewayId = gatewayId;
    }
    async stop() {
        await this.redisLocalServiceListener.disconnect();
        if (this.waitListTimer)
            await clearIntervalAsync(this.waitListTimer);
        this.waitListTimer = null;
        this.isStarted = false;
    }
    async start() {

        this.systemWatcher.on('tunnel', async (arg: { tunnel?: Tunnel, action: string }) => {
            this.waitList.push(arg);
        })

        if (this.waitListTimer)
            await clearIntervalAsync(this.waitListTimer);
        this.waitListTimer = null;
        this.waitListTimer = setIntervalAsync(async () => {
            await this.checkGatewayId();
            await this.startListening();
            await this.processWaitList();
        }, 1000);
    }
    async checkGatewayId() {
        if (!this.gatewayId) {
            try {
                this.gatewayId = await GatewayId.read(this.configFile)
            } catch (err) {
                logger.error(err);
            }
        }
    }
    async policyCalculate(item: { tunnel?: Tunnel, action: string }) {

        if (item.action == 'reset') {

            for (const room of this.roomList.values()) {
                await room.pushReset();
            }
        }
        else {
            const gatewayId = item.tunnel?.gatewayId;
            if (!gatewayId || this.gatewayId != gatewayId)//check if this tunnel belongs to this tunnel
                return;
            if (!item.tunnel?.trackId)
                return;

            for (const room of this.roomList.values()) {
                if (room.gatewayId != this.gatewayId)//check if any problem
                    continue;
                if (item.action == 'delete')
                    await room.pushDelete(item.tunnel.trackId);
                else {
                    const presult = await this.policyService.authorize(item.tunnel.trackId, room.serviceId, false, item.tunnel);
                    await room.push(item.tunnel.trackId, presult);
                }
            }

        }

    }

    async processWaitList() {

        try {
            if (this.waitList.length) {
                logger.info(`policy authz waiting list count ${this.waitList.length}`);
                if (!this.gatewayId)
                    logger.fatal('policy authz there is not gatewayId');
            }

            while (this.waitList.length) {
                const items = this.waitList.slice(0, 10000);
                //process
                for (const item of items) {
                    await this.policyCalculate(item);
                }

                this.waitList.splice(0, 10000);
            }

        } catch (err) {//we are not waiting an error here, so important otherwise memory problem occurs
            logger.fatal(err);//
        }

    }

    async replicate(gatewayId?: string, serviceId?: string, instanceId?: string) {
        try {
            if (!gatewayId || !serviceId || !instanceId) return;
            let key = `/${gatewayId}/${serviceId}/${instanceId}`;
            logger.info(`policy authz replicate to service ${key}`);

            let item = this.cache.get(key) as PolicyRoomService;
            if (item) {
                logger.info(`resetting service ${key}`);
                await item.pushReset();

            } else {
                const room = new PolicyRoomService(gatewayId, serviceId, instanceId);
                this.cache.set(key, room);
                this.roomList.set(key, room);
                logger.info(`resetting service ${key}`);
                await room.pushReset();
                await room.start();
                item = room;
            }
            await this.fillRoomService(item);
        } catch (err) {
            logger.error(err);
        }
    }
    async getRoom(gatewayId: string, serviceId: string, instanceId: string) {

        return await this.roomList.get(`/${gatewayId}/${serviceId}/${instanceId}`);
    }
    async addRoom(room: PolicyRoomService) {
        let key = `/${room.gatewayId}/${room.serviceId}/${room.instanceId}`;
        this.cache.set(key, room)
        await this.roomList.set(key, room);
    }
    async fillRoomService(room: PolicyRoomService) {
        //snapshot of tunnels
        logger.info(`policy authz filling service /${room.gatewayId}/${room.serviceId}/${room.instanceId}`)
        let allTunnels = [...this.systemWatcher.tunnels.values()];
        let filteredTunnels = allTunnels.filter(x => x.gatewayId == room.gatewayId);//only this service
        for (const tunnel of filteredTunnels) {
            if (!tunnel.trackId)
                continue;
            const pResult = await this.policyService.authorize(tunnel.trackId, room.serviceId, false, tunnel);

            logger.debug(`policy authz trackId:${tunnel.trackId} serviceId:${room.serviceId} result:${JSON.stringify(pResult)}`);
            await room.push(tunnel.trackId, pResult);
        }
    }

    async iAmAliveMessage(gatewayId?: string, serviceId?: string, instanceId?: string) {
        if (!gatewayId || !serviceId || !instanceId) return;
        let key = `/${gatewayId}/${serviceId}/${instanceId}`;
        logger.info(`i am alive service: ${key}`);
        const item = this.cache.get(key) as PolicyRoomService;
        if (item) {//cache has this item, then set ttl again
            this.cache.ttl(key, 60);
        }
        //set to the global
        let serviceKey = `/service/${gatewayId}/${serviceId}/${instanceId}`;
        await this.redisGlobal.hset(serviceKey, {
            gatewayId: gatewayId, serviceId: serviceId, instanceId: instanceId, lastSeen: new Date().getTime()
        })
        await this.redisGlobal.expire(serviceKey, 5 * 60 * 1000);

    }
    async onServiceMessage(channel: string, message: string) {
        try {

            const parts = message.split('/');
            if (!parts.length)
                return;
            if (parts[0] == 'alive') {//client sended alive
                await this.iAmAliveMessage(...parts.slice(1))
            }


            if (parts[0] == 'replicate') {
                await this.replicate(...parts.slice(1));
            }
        } catch (err) {
            logger.error(err);
        }
    }
    private onMessage = async (channel: string, message: string) => {
        await this.onServiceMessage(channel, message);
    }

    async startListening() {
        try {
            if (this.isStarted) return;

            await this.redisLocalServiceListener.onMessage(this.onMessage);
            await this.redisLocalServiceListener.subscribe(`/policy/service`);
            this.isStarted = true;
        } catch (err) {
            logger.error(err);
        }
    }


}
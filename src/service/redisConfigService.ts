import { Util } from "../util";
import { logger } from "../common";
import { ConfigService } from "./configService";
import { RedisPipelineService, RedisService } from "../service/redisService";
import { User } from "../model/user";
import { WatchService } from "./watchService";
import { pipeline } from "stream";
import { RedLockService } from "./redLockService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export class RedisConfigService extends ConfigService {

    isInitCompleted = false;
    timerInterval: any;
    timerInterval2: any;
    lastPos = '$';
    logs: any[] = [];
    isFatalError = false;
    logWatcher: WatchService;
    redLock: RedLockService;
    constructor(private redis: RedisService, private redisStream: RedisService, encryptKey: string, configFile?: string) {
        super(encryptKey, configFile);
        this.logWatcher = new WatchService(redis, redisStream, '/logs/config');
        this.redLock = new RedLockService(redis);
    }


    override loadConfigFromFile(): void {
    }
    saveConfigToFile(): void {

    }

    async start() {
        try {

            this.timerInterval = await setIntervalAsync(async () => {
                await this.init();
            }, 1000)


        } catch (err) {
            logger.error(err);
        }
    }


    async rGetAll(path: string, callback?: (vals: any[]) => void) {
        const rpath = `/config/${path}`;



        const keys = await this.redis.getAllKeys(`${rpath}/*`);
        if (keys.length) {
            const pipe = await this.redis.multi();
            keys.forEach(x => pipe.get(x));
            let items = await pipe.exec();
            items = items.map((x: string) => {
                let decrypted = x;
                if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
                    decrypted = Util.decrypt(this.getEncKey(), x, 'base64');
                }
                let val = JSON.parse(decrypted);
                return val;
            })
            if (callback)
                callback(items);
            return items;
        } else {
            if (callback)
                callback([]);
            return [];
        }

    }



    async rGet(path: string, callback?: (val: any) => Promise<any>) {
        const rpath = `/config/${path}`;

        let dataStr = await this.redis.get(rpath, false) as any;
        let decrypted = dataStr;
        if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
            decrypted = Util.decrypt(this.getEncKey(), dataStr, 'base64');
        }
        let val = JSON.parse(decrypted);
        if (callback)
            return callback(val);
        return val;
    }
    async rGetIndex(path: string, search: string) {

        let dataStr = search;
        if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
            dataStr = Util.encrypt(this.getEncKey(), dataStr, 'base64');
        }
        const rpath = `/index/config/${path}/${dataStr}`;
        return await this.redis.get(rpath, false) as any;
    }

    async rDel(path: string, data: any, pipeline?: RedisPipelineService, callback?: (val: any, pipeline?: RedisPipelineService) => Promise<any>) {
        if (data == null || data == undefined) return;
        let rpath = `/config/${path}`;
        if (typeof (data) == 'object' && data.id)
            rpath += `/${data.id}`;
        const lpipeline = pipeline || await this.redis.multi();
        await lpipeline.remove(rpath);
        await lpipeline.incr('/config/revision');
        if (callback)
            callback(data, lpipeline);
        if (!pipeline)
            await lpipeline.exec();
    }

    async rSave(path: string, data: any, pipeline?: RedisPipelineService, extra?: (data: any, pipeline: RedisPipelineService) => Promise<void>) {
        if (data == null || data == undefined) return;
        let rpath = `/config/${path}`;
        if (typeof (data) == 'object' && data.id)
            rpath += `/${data.id}`;
        let dataStr = '';
        if (typeof (data) == 'boolean' || typeof (data) == 'number' || typeof (data) == 'string' || typeof (data) == 'object')
            dataStr = JSON.stringify(data);
        else
            throw new Error('not implemented');
        let encrypted = dataStr;
        if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
            encrypted = Util.encrypt(this.getEncKey(), dataStr, 'base64');
        }

        const lpipeline = pipeline || await this.redis.multi();
        await lpipeline.set(rpath, encrypted);
        await lpipeline.incr('/config/revision');
        if (extra)
            await extra(data, lpipeline);
        await this.logWatcher.write({ path: rpath, type: 'put', data: dataStr }, lpipeline);
        if (!pipeline)
            await lpipeline.exec();

    }
    async rSaveArray(path: string, data: any[], pipeline?: RedisPipelineService, extra?: (data: any, pipeline: RedisPipelineService) => Promise<void>) {
        if (data == null || data == undefined) return;

        for (const item of data) {
            await this.rSave(path, item, pipeline, extra);
        }


    }

    async rExists(path: string, data: any) {
        if (data == null || data == undefined) return false;
        let rpath = `/config/${path}`;
        if (typeof (data) == 'object' && data.id)
            rpath += `/${data.id}`;
        return await this.redis.containsKey(rpath);
    }


    async init() {
        try {
            logger.info("config service init, trying lock");
            await this.redLock.tryLock('/lock/config', 1000, true);
            await this.redLock.lock('/lock/config', 1000, 500);
            logger.info("initting config service");

            const revisionExits = await this.rExists('revision', this.config.revision);
            if (revisionExits)
                this.config.revision = await this.rGet('revision');
            const versionExits = await this.rExists('version', this.config.version);
            if (versionExits)
                this.config.version = await this.rGet('version');

            if (!versionExits) {//if not saved before, first installing system
                logger.info("config service not saved before");
                logger.info("create default values");
                await this.saveV1();
            }
            clearIntervalAsync(this.timerInterval);
            this.timerInterval = null;
            this.isInitCompleted = true;
        } catch (err) {
            logger.error(err);
        } finally {
            this.redLock.release();
        }
    }
    async saveV1() {
        const pipeline = await this.redis.multi();
        await this.rSave('version', this.config.version, pipeline);
        await this.rSave('isConfigured', this.config.isConfigured, pipeline);

        await this.rSaveArray('users', this.config.users, pipeline,
            async (data: any, trx: RedisPipelineService) => {
                let dataStr = data.username;
                if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
                    dataStr = Util.encrypt(this.getEncKey(), dataStr, 'base64')
                }
                await trx.set(`/index/config/users/${dataStr}`, data.id);
                return data;
            });
        await this.rSaveArray('groups', this.config.groups, pipeline);
        await this.rSaveArray('services', this.config.services, pipeline);
        await this.rSave('captcha', this.config.captcha, pipeline);
        await this.rSave('jwtSSLCertificate', this.config.jwtSSLCertificate, pipeline);
        await this.rSave('sslCertificate', this.config.sslCertificate, pipeline);
        await this.rSave('caSSLCertificate', this.config.caSSLCertificate, pipeline);
        await this.rSave('domain', this.config.domain, pipeline);
        await this.rSave('url', this.config.url, pipeline);
        await this.rSave('email', this.config.email, pipeline);
        await this.rSave('logo', this.config.logo, pipeline);
        await this.rSave('auth/common', this.config.auth.common, pipeline);
        await this.rSaveArray('auth/ldap/providers', this.config.auth.ldap?.providers || [], pipeline);
        await this.rSaveArray('auth/oauth/providers', this.config.auth.oauth?.providers || [], pipeline);
        await this.rSaveArray('auth/saml/providers', this.config.auth.saml?.providers || [], pipeline);
        await this.rSaveArray('networks', this.config.networks, pipeline);
        await this.rSaveArray('gateways', this.config.gateways, pipeline);
        await this.rSaveArray('authenticationPolicy/rules', this.config.authenticationPolicy.rules, pipeline);
        await this.rSaveArray('authorizationPolicy/rules', this.config.authorizationPolicy.rules, pipeline);
        await pipeline.exec();

    }

}
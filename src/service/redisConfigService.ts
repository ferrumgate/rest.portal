import { Util } from "../util";
import { logger } from "../common";
import { ConfigService } from "./configService";
import { RedisPipelineService, RedisService } from "../service/redisService";
import { User } from "../model/user";
import { WatchService } from "./watchService";
import { pipeline } from "stream";
import { RedLockService } from "./redLockService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

type Nullable<T> = T | null | undefined;

export interface ConfigWatch<T> {
    path: string, type: 'del' | 'put', val: T
}

export class RedisConfigService extends ConfigService {

    isInitCompleted = false;
    timerInterval: any;
    timerInterval2: any;
    lastPos = '$';
    logs: any[] = [];

    logWatcher: WatchService;
    redLock: RedLockService;
    constructor(private redis: RedisService, private redisStream: RedisService,
        encryptKey: string, configFile?: string) {
        super(encryptKey, configFile);
        this.logWatcher = new WatchService(redis, redisStream, '/logs/config');
        this.redLock = new RedLockService(redis);
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


    async rGetAll<T>(path: string, callback?: (vals: T[]) => void) {
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
                let val = JSON.parse(decrypted) as T;
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



    async rGet(path: string, callback?: (val: any) => Promise<T | null>) {
        const rpath = `/config/${path}`;

        let dataStr = await this.redis.get(rpath, false) as any;
        if (dataStr) {
            let decrypted = dataStr;
            if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
                decrypted = Util.decrypt(this.getEncKey(), dataStr, 'base64');
            }
            let val = JSON.parse(decrypted);
            if (callback)
                return callback(val);
            return val;
        } else {
            if (callback)
                return callback(null);
            return null;
        }
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

        await this.logWatcher.write({ path: rpath, type: 'del', val: data }, lpipeline);
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
        await this.logWatcher.write({ path: rpath, type: 'put', val: data }, lpipeline);
        if (!pipeline)
            await lpipeline.exec();

    }
    async rSaveArray(path: string, data: any[], pipeline?: RedisPipelineService, extra?: (data: any, pipeline: RedisPipelineService) => Promise<void>) {
        if (data == null || data == undefined) return;

        for (const item of data) {
            await this.rSave(path, item, pipeline, extra);
        }


    }

    async rExists(path: string) {

        let rpath = `/config/${path}`;
        return await this.redis.containsKey(rpath);
    }


    async init() {
        try {
            logger.info("config service init, trying lock");
            await this.redLock.tryLock('/lock/config', 1000, true, 2, 250);
            await this.redLock.lock('/lock/config', 1000, 500);
            logger.info("initting config service");

            const revisionExits = await this.rExists('revision');
            if (revisionExits)
                this.config.revision = await this.rGet('revision');
            const versionExits = await this.rExists('version');
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
                let user = (data as User)
                let dataStr = user.username;
                if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
                    dataStr = Util.encrypt(this.getEncKey(), dataStr, 'base64')
                }
                await trx.set(`/index/config/users/username/${dataStr}`, data.id);
                if (user.apiKey) {
                    let dataStr = user.apiKey;
                    if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
                        dataStr = Util.encrypt(this.getEncKey(), dataStr, 'base64')
                    }
                    await trx.set(`/index/config/users/apiKey/${dataStr}`, data.id);
                }
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
        await this.rSave('lastUpdateTime', this.config.lastUpdateTime, pipeline);
        await pipeline.exec();

    }

    isEverythingOK() {
        if (!this.isInitCompleted) {
            throw new Error("config initialization error");
        }
    }

    override loadConfigFromFile(): void {
    }

    override async getLastUpdateTime() {
        return await this.rGet('lastUpdateTime')

    }
    override async saveLastUpdateTime() {
        this.config.lastUpdateTime = new Date().toISOString();
        await this.rSave('lastIpdateTime', this.config.lastUpdateTime);

    }
    override async saveConfigToFile() {
        await this.saveLastUpdateTime();
    }


    override async getUserByUsername(username: string): Promise<User | undefined> {
        this.isEverythingOK();
        if (!username) return undefined;
        const id = await this.rGetIndex('users/username', username);
        if (!id) return undefined;
        this.config.users = [];
        const user = await this.rGet(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return await super.getUserByUsername(username);
    }

    override async getUserByUsernameAndSource(username: string, source: string): Promise<User | undefined> {
        this.isEverythingOK();
        if (!username) return undefined;
        const id = await this.rGetIndex('users/username', username);
        if (!id) return undefined;
        this.config.users = [];
        const user = await this.rGet(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return await super.getUserByUsernameAndSource(username, source);
    }

    override async getUserByApiKey(key: string): Promise<User | undefined> {
        this.isEverythingOK();
        if (!key) return undefined;
        const id = await this.rGetIndex('users/apiKey', key);
        if (!id) return undefined;
        this.config.users = [];
        const user = await this.rGet(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return await super.getUserByApiKey(key);

    }
    //test start
    override async getUserById(id: string): Promise<User | undefined> {
        this.isEverythingOK();
        if (!id) return undefined;
        const user = await this.rGet(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return await super.getUserById(id);
    }

    async getUsersBy(page: number = 0, pageSize: number = 0, search?: string,
        ids?: string[], groupIds?: string[], roleIds?: string[],
        is2FA?: boolean, isVerified?: boolean, isLocked?: boolean,
        isEmailVerified?: boolean, isOnlyApiKey?: boolean) {
        this.isEverythingOK();
        this.config.users = [];
        const users = await this.rGetAll('users');
        this.config.users = users;

    }







}
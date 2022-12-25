import { Util } from "../util";
import { logger } from "../common";
import { ConfigService } from "./configService";
import { RedisPipelineService, RedisService } from "../service/redisService";
import { User } from "../model/user";
import { WatchService } from "./watchService";
import { pipeline } from "stream";
import { RedLockService } from "./redLockService";
import { AuthenticationRule } from "../model/authenticationPolicy";
import { AuthorizationRule } from "../model/authorizationPolicy";
import { Captcha } from "../model/captcha";
import { SSLCertificate } from "../model/sslCertificate";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');


type Nullable<T> = T | null | undefined;







export interface ConfigWatch<T> {
    path: string, type: 'del' | 'put', val: T, before?: T
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
    async rCount(path: string) {
        const rpath = `/config/${path}`;
        return (await this.redis.getAllKeys(rpath)).length;
    }

    async rGetAll<T>(path: string, callback?: (vals: T[]) => void) {
        const rpath = `/config/${path}`;



        const keys = await this.redis.getAllKeys(`${rpath}/*`);
        if (keys.length) {
            const pipe = await this.redis.multi();
            keys.forEach(x => pipe.get(x));
            let items = await pipe.exec();
            let elements: T[] = items.map((x: string) => {
                let decrypted = x;
                if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
                    decrypted = Util.decrypt(this.getEncKey(), x, 'base64');
                }
                let val = JSON.parse(decrypted) as T;
                return val;
            })
            if (callback)
                callback(elements);
            return elements;
        } else {
            if (callback)
                callback([]);
            return [];
        }

    }



    async rGet<Nullable>(path: string, callback?: (val: Nullable | null) => Promise<Nullable>) {
        let rpath = `/config/${path}`;

        let dataStr = await this.redis.get(rpath, false) as any;
        if (dataStr) {
            let decrypted = dataStr;
            if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
                decrypted = Util.decrypt(this.getEncKey(), dataStr, 'base64');
            }
            let val = JSON.parse(decrypted) as Nullable;
            if (callback)
                return callback(val);
            return val;
        } else {
            if (callback)
                return callback(null);
            return null;
        }
    }
    async rGetIndex<Nullable>(path: string, search: string) {

        let dataStr = search;
        if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
            dataStr = Util.encrypt(this.getEncKey(), dataStr, 'base64');
        }
        const rpath = `/index/config/${path}/${dataStr}`;
        return await this.redis.get(rpath, false) as Nullable;
    }



    async rDel<T>(path: string, data: T, pipeline?: RedisPipelineService, callback?: (val: T, pipeline: RedisPipelineService) => Promise<any>) {
        if (data == null || data == undefined) return;
        let rpath = `/config/${path}`;
        if (typeof (data) == 'object' && (data as any).id)
            rpath += `/${(data as any).id}`;
        const lpipeline = pipeline || await this.redis.multi();
        await lpipeline.remove(rpath);
        await lpipeline.incr('/config/revision');

        await this.logWatcher.write({ path: rpath, type: 'del', val: data }, lpipeline);
        if (callback)
            callback(data, lpipeline);
        if (!pipeline)
            await lpipeline.exec();
    }

    async rSave<T>(path: string, before: T | undefined, after: T,
        pipeline?: RedisPipelineService,
        extra?: (before: T | undefined, after: T, pipeline: RedisPipelineService) => Promise<void>) {
        if (after == null || after == undefined) return;
        let rpath = `/config/${path}`;
        if (typeof (after) == 'object' && (after as any).id)
            rpath += `/${(after as any).id}`;
        let dataStr = '';
        if (typeof (after) == 'boolean' || typeof (after) == 'number'
            || typeof (after) == 'string' || typeof (after) == 'object')
            dataStr = JSON.stringify(after);
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
            await extra(before, after, lpipeline);
        await this.logWatcher.write({ path: rpath, type: 'put', val: after, before: before }, lpipeline);
        if (!pipeline)
            await lpipeline.exec();

    }
    async rSaveArray<T>(path: string, data: T[], pipeline?: RedisPipelineService,
        extra?: (before: T | undefined, after: T, pipeline: RedisPipelineService) => Promise<void>) {
        if (data == null || data == undefined) return;

        for (const item of data) {
            await this.rSave<T>(path, undefined, item, pipeline, extra);
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
                this.config.revision = await this.rGet<number>('revision') || 0;
            const versionExits = await this.rExists('version');
            if (versionExits)
                this.config.version = await this.rGet<number>('version') || 0;

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
    private async saveUserIndexes(user: User, pipeline?: RedisPipelineService) {
        const trx = pipeline || await this.redis.multi();

        let dataStr = user.username;
        if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
            dataStr = Util.encrypt(this.getEncKey(), dataStr, 'base64')
        }
        await trx.set(`/index/config/users/username/${dataStr}`, user.id);
        if (user.apiKey) {
            let dataStr = user.apiKey;
            if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
                dataStr = Util.encrypt(this.getEncKey(), dataStr, 'base64')
            }
            await trx.set(`/index/config/users/apiKey/${dataStr}`, user.id);
        }
        if (!pipeline)
            await trx.exec();
    }
    async saveV1() {
        const pipeline = await this.redis.multi();
        await this.rSave('version', undefined, this.config.version, pipeline);
        await this.rSave('isConfigured', undefined, this.config.isConfigured, pipeline);

        await this.rSaveArray('users', this.config.users, pipeline,
            async (before: any, data: any, trx: RedisPipelineService) => {
                await this.saveUserIndexes(data, trx);
                return data;
            });
        await this.rSaveArray('groups', this.config.groups, pipeline);
        await this.rSaveArray('services', this.config.services, pipeline);
        await this.rSave('captcha', undefined, this.config.captcha, pipeline);
        await this.rSave('jwtSSLCertificate', undefined, this.config.jwtSSLCertificate, pipeline);
        await this.rSave('sslCertificate', undefined, this.config.sslCertificate, pipeline);
        await this.rSave('caSSLCertificate', undefined, this.config.caSSLCertificate, pipeline);
        await this.rSave('domain', undefined, this.config.domain, pipeline);
        await this.rSave('url', undefined, this.config.url, pipeline);
        await this.rSave('email', undefined, this.config.email, pipeline);
        await this.rSave('logo', undefined, this.config.logo, pipeline);
        await this.rSave('auth/common', undefined, this.config.auth.common, pipeline);
        await this.rSaveArray('auth/ldap/providers', this.config.auth.ldap?.providers || [], pipeline);
        await this.rSaveArray('auth/oauth/providers', this.config.auth.oauth?.providers || [], pipeline);
        await this.rSaveArray('auth/saml/providers', this.config.auth.saml?.providers || [], pipeline);
        await this.rSaveArray('networks', this.config.networks, pipeline);
        await this.rSaveArray('gateways', this.config.gateways, pipeline);
        await this.rSaveArray('authenticationPolicy/rules', this.config.authenticationPolicy.rules, pipeline);
        await this.rSaveArray('authorizationPolicy/rules', this.config.authorizationPolicy.rules, pipeline);
        await this.rSave('lastUpdateTime', this.config.lastUpdateTime, this.config.lastUpdateTime, pipeline);
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
        this.isEverythingOK();
        return await this.rGet<string>('lastUpdateTime') || new Date().toISOString();

    }
    override async saveLastUpdateTime(pipeline?: RedisPipelineService) {
        let val = new Date().toISOString();
        await this.rSave('lastIpdateTime', this.config.lastUpdateTime, val, pipeline);
        this.config.lastUpdateTime = val;

    }
    override async saveConfigToFile() {

    }


    override async getUserByUsername(username: string): Promise<User | undefined> {
        this.isEverythingOK();
        if (!username) return undefined;
        if (!username.trim()) return undefined;
        const id = await this.rGetIndex<string>('users/username', username);
        if (!id || !id.trim()) return undefined;
        this.config.users = [];
        const user = await this.rGet<User>(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return await super.getUserByUsername(username);
    }

    override async getUserByUsernameAndSource(username: string, source: string): Promise<User | undefined> {
        this.isEverythingOK();
        if (!username) return undefined;
        if (!username.trim()) return undefined;
        const id = await this.rGetIndex<string>('users/username', username);
        if (!id || !id.trim()) return undefined;
        this.config.users = [];
        const user = await this.rGet<User>(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return await super.getUserByUsernameAndSource(username, source);
    }

    override async getUserByApiKey(key: string): Promise<User | undefined> {
        this.isEverythingOK();
        if (!key && !key.trim()) return undefined;

        const id = await this.rGetIndex('users/apiKey', key);
        if (!id) return undefined;
        this.config.users = [];
        const user = await this.rGet<User>(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return await super.getUserByApiKey(key);

    }

    override async getUserById(id: string): Promise<User | undefined> {
        this.isEverythingOK();
        if (!id || !id.trim()) return undefined;
        this.config.users = [];
        const user = await this.rGet<User>(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return await super.getUserById(id);
    }

    override async getUsersBy(page: number = 0, pageSize: number = 0, search?: string,
        ids?: string[], groupIds?: string[], roleIds?: string[],
        is2FA?: boolean, isVerified?: boolean, isLocked?: boolean,
        isEmailVerified?: boolean, isOnlyApiKey?: boolean) {
        this.isEverythingOK();
        this.config.users = [];
        const users = await this.rGetAll<User>('users');
        this.config.users = users;

        return await super.getUsersBy(page, pageSize, search, ids, groupIds, roleIds, is2FA,
            isVerified, isLocked, isEmailVerified, isOnlyApiKey)

    }

    override async getUserByRoleIds(roleIds: string[]): Promise<User[]> {
        this.isEverythingOK();
        this.config.users = [];
        const users = await this.rGetAll<User>('users');
        this.config.users = users;
        return super.getUserByRoleIds(roleIds);
    }

    override async getUserCount() {
        this.isEverythingOK();
        this.config.users = [];
        return this.rCount('users/*');
    }

    override async getUserByUsernameAndPass(username: string, pass: string): Promise<User | undefined> {
        this.isEverythingOK();
        const id = await this.rGetIndex<string>('users/username', username);
        if (!id || !id.trim()) return undefined;
        this.config.users = [];
        const user = await this.rGet<User>(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return super.getUserByUsernameAndPass(username, pass);

    }

    override async getUserByIdAndPass(id: string, pass: string): Promise<User | undefined> {
        this.isEverythingOK();
        this.config.users = [];
        const user = await this.rGet<User>(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return super.getUserByIdAndPass(id, pass);
    }

    override async getUserSensitiveData(id: string) {
        this.isEverythingOK();
        this.config.users = [];
        const user = await this.rGet<User>(`users/${id}`);
        if (user)
            this.config.users.push(user);
        return super.getUserSensitiveData(id);
    }

    private async deleteUserIndexes(user: User, pipeline?: RedisPipelineService) {
        const trx = pipeline || await this.redis.multi();
        let dataStr = user.username;
        if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
            dataStr = Util.encrypt(this.getEncKey(), dataStr, 'base64')
        }
        await trx.remove(`/index/config/users/username/${dataStr}`);
        if (user.apiKey) {
            let dataStr = user.apiKey;
            if (this.getEncKey() && process.env.NODE_ENV !== 'development') {
                dataStr = Util.encrypt(this.getEncKey(), dataStr, 'base64')
            }
            await trx.remove(`/index/config/users/apiKey/${dataStr}`);
        }
        if (!pipeline)
            await trx.exec();
    }

    override async saveUser(data: User) {
        this.isEverythingOK();
        const id = await this.rGetIndex<string>('users/username', data.username);
        this.config.users = [];
        if (id) {
            const user = await this.rGet<User>(`users/${id}`);
            if (user) {
                this.config.users.push(user);
            }
        }
        const ret = await super.saveUser(data);
        //prepare redis
        const beforeUser = ret.before as User;
        const afterUser = ret.after as User;
        const pipeline = await this.redis.multi();
        if (beforeUser) { //delete previous indexes
            await this.deleteUserIndexes(beforeUser, pipeline);
        }
        await this.rSave('users', beforeUser, afterUser, pipeline);
        await this.saveUserIndexes(afterUser, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    async triggerUserDeleted2(user: User, pipeline: RedisPipelineService): Promise<void> {
        //check policy authentication
        let rulesAuthnChanged: { previous: AuthenticationRule, item: AuthenticationRule }[] = [];
        for (const rule of this.config.authenticationPolicy.rules) {
            const userIdIndex = rule.userOrgroupIds.findIndex(x => x == user.id);
            if (userIdIndex >= 0) {
                const prev = Util.clone(rule);
                rule.userOrgroupIds.splice(userIdIndex, 1);
                rulesAuthnChanged.push({ previous: prev, item: rule });
                await this.rSave('authenticationPolicy/rules', prev, rule, pipeline);
            }
        }

        //check authorization
        let rulesAuthzChanged: { previous: AuthorizationRule, item: AuthorizationRule }[] = [];
        for (const rule of this.config.authorizationPolicy.rules) {
            const userIdIndex = rule.userOrgroupIds.findIndex(x => x == user.id);
            if (userIdIndex >= 0) {
                const prev = Util.clone(rule);
                rule.userOrgroupIds.splice(userIdIndex, 1);
                rulesAuthzChanged.push({ previous: prev, item: rule });
                await this.rSave('authorizationPolicy/rules', prev, rule, pipeline);
            }
        }



        rulesAuthnChanged.forEach(x => {
            this.emitEvent({ type: 'updated', path: '/authenticationPolicy/rules', data: this.createTrackEvent(x.previous, x.item) })
        })
        if (rulesAuthnChanged.length) {
            this.emitEvent({ type: 'updated', path: '/authenticationPolicy' })
        }
        rulesAuthzChanged.forEach(x => {
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy/rules', data: this.createTrackEvent(x.previous, x.item) })
        })
        if (rulesAuthzChanged.length) {
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy' })
        }

        this.emitEvent({ type: 'deleted', path: '/users', data: this.createTrackEvent(user) })

    }

    override async deleteUser(id: string) {
        //dont call super method
        this.isEverythingOK();
        this.config.users = [];
        const user = await this.rGet<User>(`users/${id}`);
        if (user) {

            this.config.authenticationPolicy.rules = await this.rGetAll<AuthenticationRule>('authenticationPolicy/rules');
            this.config.authorizationPolicy.rules = await this.rGetAll<AuthorizationRule>('authorizationPolicy/rules');
            const pipeline = await this.redis.multi();
            await this.deleteUserIndexes(user, pipeline);
            await this.rDel('users', user, pipeline);
            await this.triggerUserDeleted2(user, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();


        }
        return this.createTrackEvent(user);

    }


    override async changeAdminUser(email: string, password: string) {
        this.isEverythingOK();
        const id = await this.rGetIndex<string>('users/username', 'admin');
        if (!id || !id.trim()) return;
        this.config.users = [];
        const user = await this.rGet<User>(`users/${id}`);
        if (user)
            this.config.users.push(user);

        const pipeline = await this.redis.multi();
        const ret = await super.changeAdminUser(email, password);
        if (!ret?.after) return;
        if (ret?.before)
            await this.deleteUserIndexes(ret?.before);
        await this.rSave('users', ret?.before, ret?.after, pipeline);
        await this.saveUserIndexes(ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;

    }

    override async getCaptcha(): Promise<Captcha> {
        this.isEverythingOK();
        this.config.captcha = await this.rGet<Captcha>('captcha') || {};
        return await super.getCaptcha();
    }

    override async setCaptcha(captcha: Captcha | {}) {
        this.isEverythingOK();
        this.config.captcha = await this.rGet<Captcha>('captcha') || {};
        const ret = await super.setCaptcha(captcha);
        const pipeline = await this.redis.multi();
        await this.rSave('captcha', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    override async getJWTSSLCertificate(): Promise<SSLCertificate> {
        this.isEverythingOK();
        this.config.jwtSSLCertificate = await this.rGet<SSLCertificate>('jwtSSLCertificate') || {};
        return await super.getJWTSSLCertificate();
    }

    override async setJWTSSLCertificate(cert: SSLCertificate | {}) {
        this.isEverythingOK();
        this.config.jwtSSLCertificate = await this.rGet<SSLCertificate>('jwtSSLCertificate') || {};
        const ret = await super.setJWTSSLCertificate(cert);
        const pipeline = await this.redis.multi();
        await this.rSave('jwtSSLCertificate', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    override async getCASSLCertificate(): Promise<SSLCertificate> {
        this.isEverythingOK();
        this.config.caSSLCertificate = await this.rGet<SSLCertificate>('caSSLCertificate') || {};
        return await super.getCASSLCertificate();
    }
    override async getCASSLCertificatePublic(): Promise<string | null | undefined> {
        this.isEverythingOK();
        this.config.caSSLCertificate = await this.rGet<SSLCertificate>('caSSLCertificate') || {};
        return await super.getCASSLCertificatePublic();
    }

    override async setCASSLCertificate(cert: SSLCertificate | {}) {
        this.isEverythingOK();
        this.config.caSSLCertificate = await this.rGet<SSLCertificate>('caSSLCertificate') || {};
        const ret = await super.setCASSLCertificate(cert);
        const pipeline = await this.redis.multi();
        await this.rSave('caSSLCertificate', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }









}
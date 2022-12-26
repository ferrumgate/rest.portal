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
import { EmailSettings } from "../model/emailSettings";
import { LogoSettings } from "../model/logoSettings";
import { AuthSettings, BaseOAuth, BaseSaml } from "../model/authSettings";
import { AuthCommon } from "../model/authSettings";
import { AuthLocal } from "../model/authSettings";
import { BaseLdap } from "../model/authSettings";
import { Gateway, Network } from "../model/network";
import { Group } from "../model/group";
import { Service } from "../model/service";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');


type Nullable<T> = T | null | undefined;


type RPath =
    'lastUpdateTime' |
    'revision' |
    'version' |
    'isConfigured' |
    'domain' |
    'url' |
    'auth' |
    'auth/common' |
    'auth/local' |
    'auth/oauth/providers' |
    'auth/ldap/providers' |
    'auth/saml/providers' |
    'jwtSSLCertificate' |
    'sslCertificate' |
    'caSSLCertificate' |
    'users' |
    'groups' |
    'services' |
    'captcha' |
    'email' |
    'logo' |
    'networks' |
    'gateways' |
    'authenticationPolicy/rules' |
    'authorizationPolicy/rules';

type RPathCount = 'users/*' |
    'groups/*' |
    'services/*' |
    'networks/*' |
    'gateways/*' |
    'authenticationPolicy/rules/*' |
    'authorizationPolicy/rules/*';




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
    async rCount(path: RPathCount) {
        const rpath = `/config/${path}`;
        return (await this.redis.getAllKeys(rpath)).length;
    }

    async rGetAll<T>(path: RPath, callback?: (vals: T[]) => void) {
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



    async rGet<Nullable>(path: RPath, callback?: (val: Nullable | null) => Promise<Nullable>) {
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
    async rGetWith<Nullable>(path: RPath, id: string, callback?: (val: Nullable | null) => Promise<Nullable>) {
        let rpath = `${path}/${id}`;
        return await this.rGet(rpath as RPath, callback);
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
        await this.rSave('auth/local', undefined, this.config.auth.local, pipeline);
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
        await this.rSave('lastUpdateTime', this.config.lastUpdateTime, val, pipeline);
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
        const user = await this.rGetWith<User>(`users`, id);
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
        const user = await this.rGetWith<User>(`users`, id);
        if (user)
            this.config.users.push(user);
        return await super.getUserByUsernameAndSource(username, source);
    }

    override async getUserByApiKey(key: string): Promise<User | undefined> {
        this.isEverythingOK();
        if (!key && !key.trim()) return undefined;

        const id = await this.rGetIndex('users/apiKey', key) as string;
        if (!id) return undefined;
        this.config.users = [];
        const user = await this.rGetWith<User>(`users`, id);
        if (user)
            this.config.users.push(user);
        return await super.getUserByApiKey(key);

    }

    override async getUserById(id: string): Promise<User | undefined> {
        this.isEverythingOK();
        if (!id || !id.trim()) return undefined;
        this.config.users = [];
        const user = await this.rGetWith<User>(`users`, id);
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
        return await this.rCount('users/*');
    }

    override async getUserByUsernameAndPass(username: string, pass: string): Promise<User | undefined> {
        this.isEverythingOK();
        const id = await this.rGetIndex<string>('users/username', username);
        if (!id || !id.trim()) return undefined;
        this.config.users = [];
        const user = await this.rGetWith<User>(`users`, id);
        if (user)
            this.config.users.push(user);
        return super.getUserByUsernameAndPass(username, pass);

    }

    override async getUserByIdAndPass(id: string, pass: string): Promise<User | undefined> {
        this.isEverythingOK();
        this.config.users = [];
        const user = await this.rGetWith<User>(`users`, id);
        if (user)
            this.config.users.push(user);
        return super.getUserByIdAndPass(id, pass);
    }

    override async getUserSensitiveData(id: string) {
        this.isEverythingOK();
        this.config.users = [];
        const user = await this.rGetWith<User>(`users`, id);
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
            const user = await this.rGetWith<User>(`users`, id);
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
        const user = await this.rGetWith<User>(`users`, id);
        if (user) {

            this.config.authenticationPolicy.rules = await this.rGetAll<AuthenticationRule>('authenticationPolicy/rules');
            this.config.authorizationPolicy.rules = await this.rGetAll<AuthorizationRule>('authorizationPolicy/rules');
            const pipeline = await this.redis.multi();
            await this.deleteUserIndexes(user, pipeline);
            await this.triggerUserDeleted2(user, pipeline);
            await this.rDel('users', user, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();


        }
        return this.createTrackEvent(user || undefined);

    }


    override async changeAdminUser(email: string, password: string) {
        this.isEverythingOK();
        const id = await this.rGetIndex<string>('users/username', 'admin');
        if (!id || !id.trim()) return;
        this.config.users = [];
        const user = await this.rGetWith<User>(`users`, id);
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

    //TODO test
    override async getEmailSettings(): Promise<EmailSettings> {
        this.isEverythingOK();
        this.config.email = await this.rGet<EmailSettings>('email') || {
            type: 'empty',
            fromname: '', pass: '', user: ''
        };
        return await super.getEmailSettings();
    }

    override async setEmailSettings(options: EmailSettings) {
        this.isEverythingOK();
        this.config.email = await this.rGet<EmailSettings>('email') || {
            type: 'empty',
            fromname: '', pass: '', user: ''
        };
        const ret = await super.setEmailSettings(options);
        const pipeline = await this.redis.multi();
        await this.rSave('email', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    override async getLogo(): Promise<LogoSettings> {
        this.isEverythingOK();
        this.config.logo = await this.rGet<LogoSettings>('logo') || {};
        return await super.getLogo();
    }
    override async setLogo(logo: LogoSettings | {}) {
        this.isEverythingOK();
        this.config.logo = await this.rGet<LogoSettings>('email') || {};
        const ret = await super.setLogo(logo);
        const pipeline = await this.redis.multi();
        await this.rSave('logo', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }
    async rGetAuthsettings() {
        this.config.auth.common = await this.rGet<AuthCommon>('auth/common') || {};
        this.config.auth.ldap = { providers: [] };
        this.config.auth.local = await this.rGet<AuthLocal>('auth/local') || this.createAuthLocal();
        this.config.auth.oauth = { providers: [] };
        this.config.auth.saml = { providers: [] };
        this.config.auth.ldap.providers = await this.rGetAll<BaseLdap>('auth/ldap/providers');
        this.config.auth.oauth.providers = await this.rGetAll<BaseOAuth>('auth/oauth/providers');
        this.config.auth.saml.providers = await this.rGetAll<BaseSaml>('auth/saml/providers');
    }

    override async getAuthSettings(): Promise<AuthSettings> {
        this.isEverythingOK();
        await this.rGetAuthsettings();
        return await super.getAuthSettings();

    }
    override async setAuthSettings(option: AuthSettings | {}) {
        this.isEverythingOK();
        await this.rGetAuthsettings();
        const ret = await super.setAuthSettings(option) as { before: AuthSettings, after: AuthSettings };
        const pipeline = await this.redis.multi();
        await this.rSave('auth/common', ret.before.common, ret.after, pipeline);
        await this.rSave('auth/local', ret.before, ret.after, pipeline);
        if (ret.before.ldap?.providers)
            for (const it of ret.before.ldap?.providers)
                await this.rDel('auth/ldap/providers', it, pipeline);
        if (ret.before.oauth?.providers)
            for (const it of ret.before.oauth?.providers)
                await this.rDel('auth/oauth/providers', it, pipeline);
        if (ret.before.saml?.providers)
            for (const it of ret.before.saml?.providers)
                await this.rDel('auth/saml/providers', it, pipeline)

        if (ret.after.ldap?.providers)
            for (const it of ret.after.ldap?.providers)
                await this.rSave('auth/ldap/providers', undefined, it, pipeline);
        if (ret.after.oauth?.providers)
            for (const it of ret.after.oauth?.providers)
                await this.rSave('auth/oauth/providers', undefined, it, pipeline);
        if (ret.after.saml?.providers)
            for (const it of ret.after.saml?.providers)
                await this.rSave('auth/saml/providers', undefined, it, pipeline);

        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();

        return ret;

    }

    async setAuthSettingsCommon(common: AuthCommon) {
        this.isEverythingOK();
        this.config.auth.common = await this.rGet<AuthCommon>('auth/common') || {};
        let ret = await super.setAuthSettingsCommon(common);
        const pipeline = await this.redis.multi();
        await this.rSave('auth/common', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;


    }
    override async getAuthSettingsCommon() {
        this.isEverythingOK();
        this.config.auth.common = await this.rGet<AuthCommon>('auth/common') || {};
        return super.getAuthSettingsCommon();
    }

    override async setAuthSettingsLocal(local: AuthLocal) {
        this.isEverythingOK();
        this.config.auth.local = await this.rGet<AuthLocal>('auth/local') || this.createAuthLocal();
        let ret = await super.setAuthSettingsLocal(local);
        const pipeline = await this.redis.multi();
        await this.rSave('auth/local', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }
    override async getAuthSettingsLocal() {
        this.isEverythingOK();
        this.config.auth.local = await this.rGet<AuthLocal>('auth/local') || this.createAuthLocal();
        return super.getAuthSettingsLocal();
    }


    override async getAuthSettingOAuth() {
        this.isEverythingOK();
        this.config.auth.oauth = { providers: [] };
        this.config.auth.oauth.providers = await this.rGetAll<BaseOAuth>('auth/oauth/providers');
        return await super.getAuthSettingOAuth();
    }

    override async addAuthSettingOAuth(provider: BaseOAuth) {
        this.isEverythingOK();
        this.config.auth.oauth = { providers: [] };
        this.config.auth.oauth.providers = await this.rGetAll<BaseOAuth>('auth/oauth/providers');
        let ret = await super.addAuthSettingOAuth(provider);
        const pipeline = await this.redis.multi();
        await this.rSave('auth/oauth/providers', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    override async deleteAuthSettingOAuth(id: string) {
        this.isEverythingOK();
        this.config.auth.oauth = { providers: [] };
        this.config.auth.oauth.providers = await this.rGetAll<BaseOAuth>('auth/oauth/providers');
        let ret = await super.deleteAuthSettingOAuth(id);
        if (ret.before) {//means deleted something
            const pipeline = await this.redis.multi();
            await this.rDel('auth/oauth/providers', ret.before, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
        }
        return ret;
    }


    override async getAuthSettingLdap() {
        this.isEverythingOK();
        this.config.auth.ldap = { providers: [] };
        this.config.auth.ldap.providers = await this.rGetAll<BaseLdap>('auth/ldap/providers');
        return await super.getAuthSettingLdap();
    }

    override async addAuthSettingLdap(provider: BaseLdap) {
        this.isEverythingOK();
        this.config.auth.ldap = { providers: [] };
        this.config.auth.ldap.providers = await this.rGetAll<BaseLdap>('auth/ldap/providers');
        let ret = await super.addAuthSettingLdap(provider);
        const pipeline = await this.redis.multi();
        await this.rSave('auth/ldap/providers', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    override async deleteAuthSettingLdap(id: string) {
        this.isEverythingOK();
        this.config.auth.ldap = { providers: [] };
        this.config.auth.ldap.providers = await this.rGetAll<BaseLdap>('auth/ldap/providers');
        let ret = await super.deleteAuthSettingLdap(id);
        if (ret.before) {//means deleted something
            const pipeline = await this.redis.multi();
            await this.rDel('auth/ldap/providers', ret.before, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
        }
        return ret;
    }



    override async getAuthSettingSaml() {
        this.isEverythingOK();
        this.config.auth.saml = { providers: [] };
        this.config.auth.saml.providers = await this.rGetAll<BaseSaml>('auth/saml/providers');
        return await super.getAuthSettingSaml();
    }

    override async addAuthSettingSaml(provider: BaseSaml) {
        this.isEverythingOK();
        this.config.auth.saml = { providers: [] };
        this.config.auth.saml.providers = await this.rGetAll<BaseSaml>('auth/saml/providers');
        let ret = await super.addAuthSettingSaml(provider);
        const pipeline = await this.redis.multi();
        await this.rSave('auth/saml/providers', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    override async deleteAuthSettingSaml(id: string) {
        this.isEverythingOK();
        this.config.auth.saml = { providers: [] };
        this.config.auth.saml.providers = await this.rGetAll<BaseSaml>('auth/saml/providers');
        let ret = await super.deleteAuthSettingSaml(id);
        if (ret.before) {//means deleted something
            const pipeline = await this.redis.multi();
            await this.rDel('auth/saml/providers', ret.before, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
        }
        return ret;
    }

    override async getNetwork(id: string) {
        this.isEverythingOK();
        this.config.networks = [];
        const network = await this.rGetWith<Network>(`networks`, id);
        if (network) {
            this.config.networks.push(network);
        }
        return await super.getNetwork(id);
    }
    override async getNetworkCount() {
        this.isEverythingOK();
        this.config.networks = [];
        return await this.rCount('networks/*');
    }

    override async getNetworkByName(name: string) {
        this.isEverythingOK();
        this.config.networks = await this.rGetAll('networks');
        return await super.getNetworkByName(name);
    }
    async getNetworkByGateway(gatewayId: string) {
        this.isEverythingOK();
        this.config.gateways = await this.rGetAll('gateways');
        this.config.networks = await this.rGetAll('networks');
        return await super.getNetworkByGateway(gatewayId);
    }

    async getNetworksBy(query: string) {
        this.isEverythingOK();
        this.config.networks = await this.rGetAll('networks');
        return await super.getNetworksBy(query);
    }
    async getNetworksAll() {
        this.isEverythingOK();
        this.config.networks = await this.rGetAll('networks');
        return await super.getNetworksAll();
    }

    async saveNetwork(network: Network) {
        this.isEverythingOK();
        this.config.networks = await this.rGetAll('networks');
        let ret = await super.saveNetwork(network);
        const pipeline = await this.redis.multi();
        await this.rSave('networks', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;

    }

    async triggerNetworkDeleted2(net: Network, pipeline: RedisPipelineService) {
        ////// gateways
        let changedGateways = this.config.gateways.filter(x => x.networkId == net.id);
        for (const x of changedGateways) {
            let previous = Util.clone(x);
            x.networkId = '';
            await this.rSave('gateways', previous, x, pipeline);
            this.emitEvent({ type: "updated", path: '/gateways', data: this.createTrackEvent(previous, x) })
        };

        //////////services

        let deleteServices = this.config.services.filter(x => x.networkId == net.id);
        this.config.services = this.config.services.filter(x => x.networkId != net.id);
        for (const x of deleteServices) {
            await this.rDel('services', x, pipeline);
            this.emitEvent({ type: 'deleted', path: '/services', data: this.createTrackEvent(x) });
        }

        //// policy authorization
        let deleteAuthorizationRules = this.config.authorizationPolicy.rules.filter(x => x.networkId == net.id);
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => x.networkId != net.id);
        for (const x of deleteAuthorizationRules) {
            await this.rDel('authorizationPolicy/rules', x, pipeline);
            this.emitEvent({ type: 'deleted', path: '/authorizationPolicy/rules', data: this.createTrackEvent(x) });
        };
        //check one more
        let deleteServicesId = deleteServices.map(x => x.id);
        let deleteAuthorizatonRules2 = this.config.authorizationPolicy.rules.filter(x => deleteServicesId.includes(x.serviceId));
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => !deleteServicesId.includes(x.serviceId));
        for (const x of deleteAuthorizatonRules2) {
            await this.rDel('authorizationPolicy/rules', x, pipeline);
            this.emitEvent({ type: 'deleted', path: '/authorizationPolicy/rules', data: this.createTrackEvent(x) });
        }

        if (deleteAuthorizationRules.length || deleteAuthorizatonRules2.length) {
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy' });
        }

        //policy authentication
        let deleteAuthenticationRules = this.config.authenticationPolicy.rules.filter(x => x.networkId == net.id);
        this.config.authenticationPolicy.rules = this.config.authenticationPolicy.rules.filter(x => x.networkId != net.id);
        for (const x of deleteAuthenticationRules) {
            await this.rDel('authenticationPolicy/rules', x, pipeline);
            this.emitEvent({ type: 'deleted', path: '/authenticationPolicy/rules', data: this.createTrackEvent(x) });
        }
        if (deleteAuthenticationRules.length) {
            this.emitEvent({ type: 'updated', path: '/authenticationPolicy' });
        }

        this.emitEvent({ type: 'deleted', path: '/networks', data: this.createTrackEvent(net) });

    }

    override async deleteNetwork(id: string) {
        this.isEverythingOK();

        this.config.networks = await this.rGetAll('networks');
        const network = this.config.networks.find(x => x.id == id);
        if (network) {
            this.config.gateways = await this.rGetAll('gateways');
            this.config.services = await this.rGetAll('services');
            this.config.authenticationPolicy.rules = await this.rGetAll('authenticationPolicy/rules');
            this.config.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules');
            const pipeline = await this.redis.multi();

            await this.triggerNetworkDeleted2(network, pipeline);
            await this.rDel('networks', network, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
        }
        return this.createTrackEvent(network)

    }

    override async getDomain(): Promise<string> {
        this.isEverythingOK();
        this.config.domain = await this.rGet<string>('domain') || '';
        return await super.getDomain();
    }
    async setDomain(domain: string) {
        this.isEverythingOK();
        this.config.domain = await this.rGet<string>('domain') || '';
        const ret = await super.setDomain(domain);
        const pipeline = await this.redis.multi();
        await this.rSave('domain', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }


    override async getGateway(id: string) {
        this.isEverythingOK();
        this.config.gateways = [];

        const gateway = await this.rGetWith<Gateway>(`gateways`, id);
        if (gateway) {
            this.config.gateways.push(gateway)
        }
        return await super.getGateway(id);
    }
    override async getGatewayCount() {
        this.isEverythingOK();
        this.config.gateways = [];
        return await this.rCount('gateways/*')
    }

    override async getGatewaysByNetworkId(id: string) {
        this.isEverythingOK();
        this.config.gateways = await this.rGetAll('gateways');
        return await super.getGatewaysByNetworkId(id);
    }
    override async getGatewaysBy(query: string) {
        this.isEverythingOK();
        this.config.gateways = await this.rGetAll('gateways');
        return await super.getGatewaysBy(query);
    }

    override async getGatewaysAll() {
        this.isEverythingOK();
        this.config.gateways = await this.rGetAll('gateways');
        return await super.getGatewaysAll();
    }

    override async saveGateway(gateway: Gateway) {
        this.isEverythingOK();
        this.config.gateways = await this.rGetAll('gateways');
        let ret = await super.saveGateway(gateway);
        const pipeline = await this.redis.multi();
        await this.rSave('gateways', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }
    override async deleteGateway(id: string) {
        this.isEverythingOK();
        this.config.gateways = await this.rGetAll('gateways');

        const gateway = this.config.gateways.find(x => x.id == id);
        if (gateway) {
            const pipeline = await this.redis.multi();
            await this.triggerGatewayDeleted(gateway);
            await this.rDel('gateways', gateway, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
        }
        return this.createTrackEvent(gateway);

    }


    override async getUrl(): Promise<string> {
        this.isEverythingOK();
        this.config.url = await this.rGet('url') || '';
        return super.getUrl();
    }
    override async setUrl(url: string) {
        this.isEverythingOK();
        this.config.url = await this.rGet('url') || '';
        let ret = await super.setUrl(url);
        const pipeline = await this.redis.multi();
        await this.rSave('url', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;

    }

    async getIsConfigured(): Promise<number> {
        this.isEverythingOK();
        this.config.isConfigured = await this.rGet('isConfigured') || 0;
        return await super.getIsConfigured();
    }

    async setIsConfigured(val: number) {
        this.isEverythingOK();
        this.config.isConfigured = await this.rGet<number>('isConfigured') || 0;
        let ret = await super.setIsConfigured(val);
        const pipeline = await this.redis.multi();
        await this.rSave('isConfigured', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }


    /// Group

    override async getGroup(id: string): Promise<Group | undefined> {
        this.isEverythingOK();
        this.config.groups = await this.rGetAll('groups');
        return await super.getGroup(id);

    }
    override async getGroupCount() {
        this.isEverythingOK();
        this.config.groups = [];
        return await this.rCount('groups/*');

    }

    override async getGroupsBySearch(query: string) {
        this.isEverythingOK();
        this.config.groups = await this.rGetAll('groups');
        return await super.getGroupsBySearch(query);
    }
    override async getGroupsAll() {
        this.isEverythingOK();
        this.config.groups = await this.rGetAll('groups');
        return await super.getGroupsAll();
    }

    async triggerDeleteGroup2(grp: Group, pipeline: RedisPipelineService) {

        let usersChanged: { previous: User, item: User }[] = [];
        for (const x of this.config.users) {
            let userGroupIndex = x.groupIds.findIndex(y => y == grp.id)
            if (userGroupIndex >= 0) {
                let cloned = Util.clone(x);
                x.groupIds.splice(userGroupIndex, 1);
                await this.rSave('users', cloned, x, pipeline);
                usersChanged.push({ previous: cloned, item: x })
            }
        }

        //check policy authentication

        let rulesAuthnChanged: { previous: AuthenticationRule, item: AuthenticationRule }[] = [];
        for (const x of this.config.authenticationPolicy.rules) {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == grp.id);
            if (userIdIndex >= 0) {
                let cloned = Util.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);
                await this.rSave('authenticationPolicy/rules', cloned, x, pipeline);
                rulesAuthnChanged.push({ previous: cloned, item: x });
            }
        }
        //check authorization

        let rulesAuthzChanged: { previous: AuthorizationRule, item: AuthorizationRule }[] = [];
        for (const x of this.config.authorizationPolicy.rules) {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == grp.id);
            if (userIdIndex >= 0) {
                let cloned = Util.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);
                await this.rSave('authorizationPolicy/rules', cloned, x, pipeline);
                rulesAuthzChanged.push({ previous: cloned, item: x });
            }
        }

        usersChanged.forEach(x => {
            this.emitEvent({ type: 'updated', path: '/users', data: this.createTrackEvent(x.previous, x.item) })
        })

        rulesAuthnChanged.forEach(x => {
            this.emitEvent({ type: 'updated', path: '/authenticationPolicy/rules', data: this.createTrackEvent(x.previous, x.item) })
        })
        if (rulesAuthnChanged.length)
            this.emitEvent({ type: 'updated', path: '/authenticationPolicy' })
        rulesAuthzChanged.forEach(x => {
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy/rules', data: this.createTrackEvent(x.previous, x.item) })
        })
        if (rulesAuthzChanged.length)
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy' })

        this.emitEvent({ type: 'deleted', path: '/groups', data: this.createTrackEvent(grp) })



    }

    override  async deleteGroup(id: string) {
        this.isEverythingOK();
        this.config.groups = await this.rGetAll('groups');

        const group = this.config.groups.find(x => x.id == id);
        if (group) {
            this.config.users = await this.rGetAll('users');
            this.config.authenticationPolicy.rules = await this.rGetAll('authenticationPolicy/rules');
            this.config.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules');

            const pipeline = await this.redis.multi();
            await this.triggerDeleteGroup2(group, pipeline);
            await this.rDel('groups', group, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();

        }
        return this.createTrackEvent(group);


    }

    override async saveGroup(group: Group) {
        this.isEverythingOK();
        this.config.groups = await this.rGetAll('groups');

        let ret = await super.saveGroup(group);
        const pipeline = await this.redis.multi();
        await this.rSave('groups', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;

    }


    override  async getService(id: string): Promise<Service | undefined> {
        this.isEverythingOK();
        this.config.services = await this.rGetAll('services');
        return await super.getService(id);

    }
    override async getServiceCount() {
        this.isEverythingOK();
        this.config.services = [];
        return await this.rCount('services/*');
    }

    override async getServicesBy(query?: string, networkIds?: string[], ids?: string[]) {
        this.isEverythingOK();
        this.config.services = await this.rGetAll('services');
        return await super.getServicesBy(query, networkIds, ids);
    }

    override async getServicesByNetworkId(networkId: string) {
        this.isEverythingOK();
        this.config.services = await this.rGetAll('services');
        return await super.getServicesByNetworkId(networkId);
    }

    //// service entity
    override async getServicesAll(): Promise<Service[]> {

        this.isEverythingOK();
        this.config.services = await this.rGetAll('services');
        return await super.getServicesAll();

    }


    async triggerServiceDeleted2(svc: Service, pipeline: RedisPipelineService) {

        //check authorization
        let rulesAuthzChanged = this.config.authorizationPolicy.rules.filter(x => x.serviceId == svc.id);
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => x.serviceId != svc.id);
        for (const x of rulesAuthzChanged) {
            await this.rDel('authorizationPolicy/rules', x, pipeline);
            this.emitEvent({ type: 'deleted', path: '/authorizationPolicy/rules', data: this.createTrackEvent(x) })
        }
        if (rulesAuthzChanged.length)
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy' })

        this.emitEvent({ type: 'deleted', path: '/services', data: this.createTrackEvent(svc) })

    }

    override async deleteService(id: string) {
        this.isEverythingOK();
        this.config.services = await this.rGetAll('services');

        const svc = this.config.services.find(x => x.id == id);
        if (svc) {
            this.config.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules')
            const pipeline = await this.redis.multi();
            await this.triggerServiceDeleted2(svc, pipeline);
            await this.rDel('services', svc, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
        }
        return this.createTrackEvent(svc);//return deleted service for log if exists
    }

    override async saveService(service: Service) {
        this.isEverythingOK();
        this.config.services = await this.rGetAll('services');
        let ret = await super.saveService(service);
        const pipeline = await this.redis.multi();
        await this.rSave('services', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    //authentication policy rule
    override async saveAuthenticationPolicyRule(arule: AuthenticationRule) {
        this.isEverythingOK();
        this.config.authenticationPolicy.rules = await this.rGetAll('authenticationPolicy/rules');
        let ret = await super.saveAuthenticationPolicyRule(arule);
        const pipeline = await this.redis.multi();
        await this.rSave('authenticationPolicy/rules', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }
    override async getAuthenticationPolicy() {
        this.isEverythingOK();
        this.config.authenticationPolicy.rules = await this.rGetAll('authenticationPolicy/rules');
        return await super.getAuthenticationPolicy();
    }

    override async getAuthenticationPolicyUnsafe() {
        this.isEverythingOK();
        this.config.authenticationPolicy.rules = await this.rGetAll('authenticationPolicy/rules');
        return await super.getAuthenticationPolicyUnsafe();
    }
    override async getAuthenticationPolicyRule(id: string) {
        this.isEverythingOK();
        this.config.authenticationPolicy.rules = await this.rGetAll('authenticationPolicy/rules');
        return await super.getAuthenticationPolicyRule(id);

    }
    override async getAuthenticationPolicyRuleCount() {
        this.isEverythingOK();
        return await this.rCount('authenticationPolicy/rules/*');

    }

    override async deleteAuthenticationPolicyRule(id: string) {
        this.isEverythingOK();
        this.config.authenticationPolicy.rules = await this.rGetAll('authenticationPolicy/rules');


        const rule = this.config.authenticationPolicy.rules.find(x => x.id == id);
        if (rule) {

            const pipeline = await this.redis.multi();
            await this.rDel('authenticationPolicy/rules', rule, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
            this.emitEvent({ type: 'deleted', path: '/authenticationPolicy/rules', data: this.createTrackEvent(rule) })
            this.emitEvent({ type: 'updated', path: '/authenticationPolicy' })

        }
        return this.createTrackEvent(rule);
    }

    override  async updateAuthenticationRulePos(id: string, previous: number, index: number) {
        const currentRule = this.config.authenticationPolicy.rules[previous];
        if (currentRule.id != id)
            throw new Error('no rule found at this position');
        if (previous < 0)
            throw new Error('array index can be negative');


        this.config.authenticationPolicy.rules.splice(previous, 1);
        this.config.authenticationPolicy.rules.splice(index, 0, currentRule);
        //TODO how to manage
        this.emitEvent({ type: 'updated', path: '/authenticationPolicy/rules', data: this.createTrackIndexEvent(currentRule, previous, index) })
        this.emitEvent({ type: 'updated', path: '/authenticationPolicy' })
        return this.createTrackIndexEvent(currentRule, previous, index);


    }



    //authorization policy

    async saveAuthorizationPolicyRule(arule: AuthorizationRule) {
        this.isEverythingOK();
        this.config.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules');
        let ret = await super.saveAuthorizationPolicyRule(arule);
        const pipeline = await this.redis.multi();
        await this.rSave('authorizationPolicy/rules', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;

    }
    async getAuthorizationPolicy() {
        this.isEverythingOK();
        this.config.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules');
        return await super.getAuthorizationPolicy();
    }
    async getAuthorizationPolicyUnsafe() {
        this.isEverythingOK();
        this.config.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules');
        return await super.getAuthorizationPolicyUnsafe();
    }
    async getAuthorizationPolicyRule(id: string) {
        this.isEverythingOK();
        this.config.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules');
        return await super.getAuthorizationPolicyRule(id);
    }

    async getAuthorizationPolicyRuleCount() {
        this.isEverythingOK();
        return await this.rCount('authorizationPolicy/rules/*');
    }
    async deleteAuthorizationPolicyRule(id: string) {
        this.isEverythingOK();
        this.config.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules');

        const rule = this.config.authorizationPolicy.rules.find(x => x.id == id);
        if (rule) {
            const pipeline = await this.redis.multi();
            await this.rDel('authorizationPolicy/rules', rule, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
            this.emitEvent({ type: 'deleted', path: '/authorizationPolicy/rules', data: this.createTrackEvent(rule) })
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy' })

        }
        return this.createTrackEvent(rule);
    }

































}
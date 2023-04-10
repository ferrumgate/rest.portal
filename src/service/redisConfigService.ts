import { Util } from "../util";
import { logger } from "../common";
import { ConfigService } from "./configService";
import { RedisPipelineService, RedisService } from "../service/redisService";
import { User } from "../model/user";
import { WatchItem, WatchService } from "./watchService";
import { pipeline } from "stream";
import { RedLockService } from "./redLockService";
import { AuthenticationRule } from "../model/authenticationPolicy";
import { AuthorizationRule } from "../model/authorizationPolicy";
import { Captcha } from "../model/captcha";
import { SSLCertificate, SSLCertificateCategory, SSLCertificateEx } from "../model/cert";
import { EmailSetting } from "../model/emailSetting";
import { LogoSetting } from "../model/logoSetting";
import { AuthSettings, BaseOAuth, BaseSaml } from "../model/authSettings";
import { AuthCommon } from "../model/authSettings";
import { AuthLocal } from "../model/authSettings";
import { BaseLdap } from "../model/authSettings";
import { Gateway, Network } from "../model/network";
import { Group } from "../model/group";
import { Service } from "../model/service";
import NodeCache from "node-cache";
import { RestfullException } from "../restfullException";
import { ErrorCodes } from "../restfullException";
import { SystemLogService } from "./systemLogService";
import { ESSetting } from "../model/esSetting";
import { Config, ConfigWatch, RPath } from "../model/config";
import { ConfigLogService } from "./configLogService";
import { IpIntelligenceList, IpIntelligenceSource } from "../model/IpIntelligence";
import { IpIntelligenceFilterCategory } from "../model/IpIntelligence";
import { IpIntelligenceCountryList } from "../model/IpIntelligence";
import IPCIDR from "ip-cidr";
import { isIPv4 } from "net";
import * as ipaddr from 'ip-address';
import { UtilPKI } from "../utilPKI";

const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');




// there paths are select count(*)
export type RPathCount = 'users/*' |
    'groups/*' |
    'services/*' |
    'networks/*' |
    'gateways/*' |
    'authenticationPolicy/rules/*' |
    'authorizationPolicy/rules/*';





/**
 * @summary save all config to rdis
 */
export class RedisConfigService extends ConfigService {

    isInitCompleted = false;
    timerInterval: any;
    //timerInterval2: any;
    //lastPos = '$';
    //logs: any[] = [];

    logWatcher: ConfigLogService;
    systemLogWatcher: SystemLogService;
    redLock: RedLockService;
    constructor(private redis: RedisService, private redisStream: RedisService,
        systemLog: SystemLogService,
        encryptKey: string,
        uniqueName = 'redisconfig', configFile?: string, logWatcherWaitMS = 1000) {
        super(encryptKey, configFile);
        this.systemLogWatcher = systemLog;
        this.logWatcher =
            new ConfigLogService(this.redis, this.redisStream, encryptKey, uniqueName + '/pos',
                logWatcherWaitMS);
        this.redLock = new RedLockService(this.redis);
    }


    override async start() {
        try {

            this.timerInterval = setIntervalAsync(async () => {
                await this.init();
            }, 1000)


        } catch (err) {
            logger.error(err);
        }
    }
    override async stop() {
        if (this.timerInterval)
            clearIntervalAsync(this.timerInterval);
        this.timerInterval = null;
        await this.logWatcherStop();

    }
    protected async logWatcherStop() {
        await this.logWatcher.stop(false);
    }
    pathCalculate(path: RPath | RPathCount) {
        return path.startsWith('/') ? `/config${path}` : `/config/${path}`
    }
    async rCount(path: RPathCount) {
        const rpath = this.pathCalculate(path);
        return (await this.redis.getAllKeys(rpath)).length;
    }

    async rGetAll<T>(path: RPath, callback?: (vals: T[]) => void) {
        const rpath = this.pathCalculate(path);

        const keys = await this.redis.getAllKeys(`${rpath}/*`);

        if (keys.length) {

            const pipe = await this.redis.pipeline();
            for (const k of keys) {
                await pipe.get(k, false);
            }
            let items = await pipe.exec();
            let elements: T[] = items.map((x: string) => {
                let decrypted = Buffer.from(x, 'base64url');// x;
                if (this.getEncKey()) {
                    decrypted = Util.jdecrypt(this.getEncKey(), decrypted);// Util.decrypt(this.getEncKey(), x, 'base64url');
                }
                let val = Util.jdecode(decrypted) as T;// JSON.parse(decrypted) as T;
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

    async rListAll<T>(path: RPath, callback?: (vals: string[]) => T[]) {
        const rpath = this.pathCalculate(path);
        const len = Util.convertToNumber(await this.redis.llen(rpath));
        if (len) {
            const items = await this.redis.lrange(rpath, 0, len);
            if (callback)
                return callback(items);
            return items;
        } else return [];
    }
    async rListGetIndex<T>(path: RPath, index: number) {
        const rpath = this.pathCalculate(path);
        return await this.redis.lindex(rpath, index);
    }
    async rListDel(path: RPath, val: string | number, pipeline?: RedisPipelineService) {
        const rpath = this.pathCalculate(path);
        const trx = pipeline || await this.redis.multi();

        await trx.lrem(rpath, val);
        const log = { path: rpath, type: 'del', val: val };
        await this.logWatcher.write(log, trx);
        await this.systemLogWatcher.write(log, trx);
        if (!pipeline)
            await trx.exec();
    }
    async rListAdd(path: RPath, val: string | number, pushBack: boolean, pipeline?: RedisPipelineService) {
        const rpath = this.pathCalculate(path);
        const trx = pipeline || await this.redis.multi();
        if (pushBack)
            await trx.rpush(rpath, [val]);
        else await trx.lpush(rpath, [val]);
        const log = { path: rpath, type: 'put', val: val };
        await this.logWatcher.write(log, trx);
        await this.systemLogWatcher.write(log, trx);
        if (!pipeline)
            await trx.exec();
    }
    async rListInsert(path: RPath, val: string | number, refPos: 'BEFORE' | 'AFTER', refVal: string | number, previous: number, current: number, total: number, pipeline?: RedisPipelineService) {
        const rpath = this.pathCalculate(path);
        const trx = pipeline || await this.redis.multi();
        /* if (current == 0)
            await trx.lpush(rpath, [val]);
        else
            if (current == total - 1)
                await trx.rpush(rpath, [val]);
            else */
        if (refPos == 'BEFORE')
            await trx.linsertBefore(rpath, refVal, val);
        else await trx.linsertAfter(rpath, refVal, val);
        const log = { path: rpath, type: 'put', val: { id: val, previous: previous, current: current } };
        await this.logWatcher.write(log, trx);
        await this.systemLogWatcher.write(log, trx);
        if (!pipeline)
            await trx.exec();
    }
    async rListLen(path: RPath) {
        const rpath = this.pathCalculate(path);
        return await this.redis.llen(rpath);
    }

    async rGetDirect<T extends number>(path: RPath, callback?: (val: any) => Promise<any>) {
        let rpath = this.pathCalculate(path);
        let dataStr = await this.redis.get(rpath, false) as any;
        if (dataStr) {
            let val = Util.convertToNumber(dataStr)
            if (callback)
                return callback(val);
            return val;
        } else {
            if (callback)
                return callback(null);
            return null;
        }
    }

    async rGet<Nullable>(path: RPath, callback?: (val: Nullable | null) => Promise<Nullable>) {
        let rpath = this.pathCalculate(path);

        let dataStr = await this.redis.get(rpath, false) as any;
        if (dataStr) {
            let decrypted = Buffer.from(dataStr, 'base64url');
            if (this.getEncKey()) {
                decrypted = Util.jdecrypt(this.getEncKey(), decrypted);// Util.decrypt(this.getEncKey(), dataStr, 'base64url');
            }
            let val = Util.jdecode(decrypted) as Nullable;//JSON.parse(decrypted) as Nullable;
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
        if (this.getEncKey()) {
            dataStr = Util.jencrypt(this.getEncKey(), dataStr).toString('base64url'); //Util.encrypt(this.getEncKey(), dataStr, 'base64url');
        }
        const rpath = `/config/index/${path}/${dataStr}`;
        return await this.redis.get(rpath, false) as Nullable;
    }



    async rDel<T>(path: RPath, data: T, pipeline?: RedisPipelineService, callback?: (val: T, pipeline: RedisPipelineService) => Promise<any>) {
        if (data == null || data == undefined) return;
        let rpath = this.pathCalculate(path);
        let wrpath = this.pathCalculate(path);
        if (typeof (data) == 'object' && (data as any).id)
            rpath += `/${(data as any).id}`;
        const lpipeline = pipeline || await this.redis.multi();
        await lpipeline.remove(rpath);
        await lpipeline.incr('/config/revision');
        const log = { path: wrpath, type: 'del', val: data };
        await this.logWatcher.write(log, lpipeline);
        await this.systemLogWatcher.write(log, lpipeline);
        if (callback)
            callback(data, lpipeline);
        if (!pipeline)
            await lpipeline.exec();
    }

    async rSave<T>(path: RPath, before: T | undefined, after: T,
        pipeline?: RedisPipelineService,
        extra?: (before: T | undefined, after: T, pipeline: RedisPipelineService) => Promise<void>) {
        if (after == null || after == undefined) return;
        let rpath = this.pathCalculate(path);
        let wrpath = this.pathCalculate(path);
        if (typeof (after) == 'object' && (after as any).id)
            rpath += `/${(after as any).id}`;
        let dataStr;// = '';
        if (typeof (after) == 'boolean' || typeof (after) == 'number'
            || typeof (after) == 'string' || typeof (after) == 'object')
            dataStr = Util.jencode(after);// JSON.stringify(after);
        else
            throw new Error('not implemented');
        let encrypted = dataStr;
        if (this.getEncKey()) {
            encrypted = Util.jencrypt(this.getEncKey(), dataStr);//Util.encrypt(this.getEncKey(), dataStr, 'base64url');
        }

        const lpipeline = pipeline || await this.redis.multi();
        await lpipeline.set(rpath, encrypted.toString('base64url'));
        await lpipeline.incr('/config/revision');
        if (extra)
            await extra(before, after, lpipeline);
        const log = { path: wrpath, type: 'put', val: after, before: before }
        await this.logWatcher.write(log, lpipeline);
        await this.systemLogWatcher.write(log, lpipeline)
        if (!pipeline)
            await lpipeline.exec();

    }
    async rSaveArray<T>(path: RPath, data: T[], pipeline?: RedisPipelineService,
        extra?: (before: T | undefined, after: T, pipeline: RedisPipelineService) => Promise<void>) {
        if (data == null || data == undefined) return;

        for (const item of data) {
            await this.rSave<T>(path, undefined, item, pipeline, extra);
        }


    }
    async rFlushAll(pipeline?: RedisPipelineService) {
        const keys = await this.redis.getAllKeys('/config/*');
        const lpipeline = pipeline || await this.redis.multi();
        //const path = '/config/*';
        await lpipeline.del(keys);
        const log = { path: '/config/flush', type: 'put', val: 1, before: 0 }
        await this.logWatcher.write(log, lpipeline);
        await this.systemLogWatcher.write(log, lpipeline)
        if (!pipeline)
            await lpipeline.exec();
    }


    async rExists(path: string) {

        let rpath = `/config/${path}`;

        return await this.redis.containsKey(rpath);
    }
    override clone<T>(data: T): T {
        return data;
    }


    override async init() {
        try {
            logger.info("config service init, trying lock");
            await this.redLock.tryLock('/lock/config', 1000, true, 2, 250);
            await this.redLock.lock('/lock/config', 1000, 500);
            logger.info("initting config service");

            const revisionExits = await this.rExists('revision');
            if (revisionExits)
                this.config.revision = await this.rGetDirect<number>('revision') || 0;
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
            await this.logWatcherStart()
            await this.afterInit();
            this.events.emit('ready');
            logger.info("initted config service");
        } catch (err) {
            logger.error(err);
        } finally {
            this.redLock.release();
        }
    }
    protected async afterInit() {

    }


    protected async logWatcherStart() {
        await this.logWatcher.start(false);
    }
    private async saveUserIndexes(user: User, pipeline?: RedisPipelineService) {
        const trx = pipeline || await this.redis.multi();

        let dataStr = user.username;
        if (this.getEncKey()) {
            dataStr = Util.jencrypt(this.getEncKey(), dataStr).toString('base64url');//Util.encrypt(this.getEncKey(), dataStr, 'base64url')
        }
        await trx.set(`/config/index/users/username/${dataStr}`, user.id);
        if (user.apiKey) {
            let dataStr = user.apiKey;
            if (this.getEncKey()) {
                dataStr = Util.jencrypt(this.getEncKey(), dataStr).toString('base64url');//  Util.encrypt(this.getEncKey(), dataStr, 'base64url')
            }
            await trx.set(`/config/index/users/apiKey/${dataStr}`, user.id);
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
        await this.rSave('webSSLCertificate', undefined, this.config.webSSLCertificate, pipeline);
        await this.rSave('caSSLCertificate', undefined, this.config.caSSLCertificate, pipeline);
        await this.rSaveArray('inSSLCertificates', this.config.inSSLCertificates, pipeline);
        await this.rSave('domain', undefined, this.config.domain, pipeline);
        await this.rSave('url', undefined, this.config.url, pipeline);
        await this.rSave('email', undefined, this.config.email, pipeline);
        await this.rSave('logo', undefined, this.config.logo, pipeline);
        await this.rSave('auth/common', undefined, this.config.auth.common, pipeline);
        await this.rSave('auth/local', undefined, this.config.auth.local, pipeline);
        await this.rSaveArray('auth/ldap/providers', this.config.auth.ldap.providers || [], pipeline);
        await this.rSaveArray('auth/oauth/providers', this.config.auth.oauth.providers || [], pipeline);
        await this.rSaveArray('auth/saml/providers', this.config.auth.saml.providers || [], pipeline);
        await this.rSaveArray('networks', this.config.networks, pipeline);
        await this.rSaveArray('gateways', this.config.gateways, pipeline);
        await this.rSaveArray('authenticationPolicy/rules', this.config.authenticationPolicy.rules, pipeline);
        for (const order of this.config.authenticationPolicy.rulesOrder) {
            await this.rListAdd('authenticationPolicy/rulesOrder', order, true, pipeline);
        }
        await this.rSaveArray('authorizationPolicy/rules', this.config.authorizationPolicy.rules, pipeline);
        for (const order of this.config.authorizationPolicy.rulesOrder) {
            await this.rListAdd('authorizationPolicy/rulesOrder', order, true, pipeline);
        }
        await this.rSave('lastUpdateTime', this.config.lastUpdateTime, this.config.lastUpdateTime, pipeline);
        //create certs

        {
            const { publicCrt, privateKey } = await UtilPKI.createCert('FerrumGate JWT CA', 'ferrumgate', 9125, true, []);
            await this.rSave('jwtSSLCertificate', undefined, {
                ...this.config.jwtSSLCertificate,
                privateKey: privateKey,
                publicCrt: publicCrt,
                isSystem: true
            }, pipeline);
        }
        let caPublicCrt, caPrivateKey;
        {
            const { publicCrt, privateKey } = await UtilPKI.createCert('FerrumGate ROOT CA', 'ferrumgate', 9125, true, []);
            await this.rSave('caSSLCertificate', undefined, {
                ...this.config.caSSLCertificate,
                privateKey: privateKey,
                publicCrt: publicCrt,
                isSystem: true
            }, pipeline);
            caPublicCrt = publicCrt;
            caPrivateKey = privateKey;

        }

        let inTls: SSLCertificateEx;
        {
            const { publicCrt, privateKey } = await UtilPKI.createCertSigned('FerrumGate Intermediate TLS', 'ferrumgate', 9125, true, [], caPublicCrt, caPrivateKey);
            inTls = {
                ...this.defaultCertificate('FerrumGate Intermediate TLS', 'tls'),
                id: Util.randomNumberString(16),
                parentId: this.config.caSSLCertificate.idEx,
                publicCrt: publicCrt,
                privateKey: privateKey,
                isSystem: false,
                usages: ['for web', 'for tls inspection', 'for service']

            }
            await this.rSave('inSSLCertificates', undefined, inTls, pipeline);
        }

        //create a default authentication intermediate certs
        let inAuthentication: SSLCertificateEx;
        {
            const { publicCrt, privateKey } = await UtilPKI.createCertSigned('FerrumGate Intermediate Authentication', 'ferrumgate', 9125, true, [], caPublicCrt, caPrivateKey);
            inAuthentication = {
                ...this.defaultCertificate('FerrumGate Intermediate Authentication', 'auth'),
                id: Util.randomNumberString(16),
                parentId: this.config.caSSLCertificate.idEx,
                publicCrt: publicCrt,
                privateKey: privateKey,

            }
            await this.rSave('inSSLCertificates', undefined, inAuthentication, pipeline);
        }


        //save web certtificate
        {
            //sign with intermediate web
            const url = await this.config.url;
            const domain1 = new URL(url).hostname;
            const { publicCrt, privateKey } = await UtilPKI.createCertSigned(domain1, 'ferrumgate', 3650, false,
                [
                    { type: 'domain', value: domain1 },

                ], inTls.publicCrt, inTls.privateKey);
            let cert: SSLCertificate = {
                ...this.config.webSSLCertificate,
                parentId: inTls.id,
                publicCrt: publicCrt,
                privateKey: privateKey,

            }

            await this.rSave('webSSLCertificate', undefined, cert, pipeline);
        }

        await pipeline.exec();

    }

    override emitEvent<T>(event: ConfigWatch<T>): void {
        // we need to disabled this,
        // with redis, every change is written to /logs/config file,
        // clients need to follow that file, about changes
    }
    override publishEvent(ev: string, data?: any): void {
        // disable all base events
    }


    override async saveConfigToString() {

        await this.getConfig();
        return await super.saveConfigToString();

    }

    override isReady() {
        if (!this.isInitCompleted) {
            throw new RestfullException(412, ErrorCodes.ErrSystemIsNotReady, ErrorCodes.ErrSystemIsNotReady, 'config is not ready');
        }
    }

    override loadConfigFromFile(): void {
    }

    override async getLastUpdateTime() {
        this.isReady();
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
        this.isReady();
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
        this.isReady();
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
        this.isReady();
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
        this.isReady();
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
        this.isReady();
        this.config.users = [];
        const users = await this.rGetAll<User>('users');
        this.config.users = users;

        return await super.getUsersBy(page, pageSize, search, ids, groupIds, roleIds, is2FA,
            isVerified, isLocked, isEmailVerified, isOnlyApiKey)

    }

    override async getUserByRoleIds(roleIds: string[]): Promise<User[]> {
        this.isReady();
        this.config.users = [];
        const users = await this.rGetAll<User>('users');
        this.config.users = users;
        return super.getUserByRoleIds(roleIds);
    }

    override async getUserCount() {
        this.isReady();
        this.config.users = [];
        return await this.rCount('users/*');
    }

    override async getUserByUsernameAndPass(username: string, pass: string): Promise<User | undefined> {
        this.isReady();
        const id = await this.rGetIndex<string>('users/username', username);
        if (!id || !id.trim()) return undefined;
        this.config.users = [];
        const user = await this.rGetWith<User>(`users`, id);
        if (user)
            this.config.users.push(user);
        return super.getUserByUsernameAndPass(username, pass);

    }

    override async getUserByIdAndPass(id: string, pass: string): Promise<User | undefined> {
        this.isReady();
        this.config.users = [];
        const user = await this.rGetWith<User>(`users`, id);
        if (user)
            this.config.users.push(user);
        return super.getUserByIdAndPass(id, pass);
    }

    override async getUserSensitiveData(id: string) {
        this.isReady();
        this.config.users = [];
        const user = await this.rGetWith<User>(`users`, id);
        if (user)
            this.config.users.push(user);
        return super.getUserSensitiveData(id);
    }

    private async deleteUserIndexes(user: User, pipeline?: RedisPipelineService) {
        const trx = pipeline || await this.redis.multi();
        let dataStr = user.username;
        if (this.getEncKey()) {
            dataStr = Util.jencrypt(this.getEncKey(), dataStr).toString('base64url');// Util.encrypt(this.getEncKey(), dataStr, 'base64url')
        }
        await trx.remove(`/config/index/users/username/${dataStr}`);
        if (user.apiKey) {
            let dataStr = user.apiKey;
            if (this.getEncKey()) {
                dataStr = Util.jencrypt(this.getEncKey(), dataStr).toString('base64url');//Util.encrypt(this.getEncKey(), dataStr, 'base64url')
            }
            await trx.remove(`/config/index/users/apiKey/${dataStr}`);
        }
        if (!pipeline)
            await trx.exec();
    }

    override async saveUser(data: User) {
        this.isReady();
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


    }

    override async deleteUser(id: string) {
        //dont call super method
        this.isReady();
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
        this.isReady();
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
        this.isReady();
        this.config.captcha = await this.rGet<Captcha>('captcha') || {};
        return await super.getCaptcha();
    }

    override async setCaptcha(captcha: Captcha | {}) {
        this.isReady();
        this.config.captcha = await this.rGet<Captcha>('captcha') || {};
        const ret = await super.setCaptcha(captcha);
        const pipeline = await this.redis.multi();
        await this.rSave('captcha', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    override async getJWTSSLCertificateSensitive(): Promise<SSLCertificate> {
        this.isReady();
        this.config.jwtSSLCertificate = await this.rGet<SSLCertificate>('jwtSSLCertificate') || this.defaultCertificate('JWT', 'jwt');
        return await super.getJWTSSLCertificateSensitive();
    }


    override async setJWTSSLCertificate(cert: SSLCertificate | {}) {
        this.isReady();
        this.config.jwtSSLCertificate = await this.rGet<SSLCertificate>('jwtSSLCertificate') || this.defaultCertificate('JWT', 'jwt');
        const ret = await super.setJWTSSLCertificate(cert);
        const pipeline = await this.redis.multi();
        await this.rSave('jwtSSLCertificate', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    override async getWebSSLCertificateSensitive(): Promise<SSLCertificate> {
        this.isReady();
        this.config.webSSLCertificate = await this.rGet<SSLCertificate>('webSSLCertificate') || this.defaultCertificate('Web', 'web');
        return await super.getWebSSLCertificateSensitive();
    }

    override async setWebSSLCertificate(cert: SSLCertificate | {}) {
        this.isReady();
        this.config.webSSLCertificate = await this.rGet<SSLCertificate>('webSSLCertificate') || this.defaultCertificate('Web', 'web');
        const ret = await super.setWebSSLCertificate(cert);
        const pipeline = await this.redis.multi();
        await this.rSave('webSSLCertificate', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    override async getCASSLCertificateSensitive(): Promise<SSLCertificate> {
        this.isReady();
        this.config.caSSLCertificate = await this.rGet<SSLCertificate>('caSSLCertificate') || this.defaultCertificate('CA', 'ca');
        return await super.getCASSLCertificateSensitive();
    }


    override async setCASSLCertificate(cert: SSLCertificate | {}) {
        this.isReady();
        this.config.caSSLCertificate = await this.rGet<SSLCertificate>('caSSLCertificate') || this.defaultCertificate('CA', 'ca');
        const ret = await super.setCASSLCertificate(cert);
        const pipeline = await this.redis.multi();
        await this.rSave('caSSLCertificate', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    //intermedidate certificates
    /// Group

    override async getInSSLCertificateSensitive(id: string): Promise<SSLCertificateEx | undefined> {
        this.isReady();
        this.config.inSSLCertificates = await this.rGetAll('inSSLCertificates');
        return await super.getInSSLCertificateSensitive(id);

    }

    override async getInSSLCertificateAllSensitive() {
        this.isReady();
        this.config.inSSLCertificates = await this.rGetAll('inSSLCertificates');
        return await super.getInSSLCertificateAllSensitive();
    }


    override  async deleteInSSLCertificate(id: string) {
        this.isReady();
        this.config.inSSLCertificates = [];
        const cert = await this.rGetWith<SSLCertificateEx>('inSSLCertificates', id);

        if (cert) {
            this.config.inSSLCertificates.push(cert);

            const pipeline = await this.redis.multi();

            await this.rDel('inSSLCertificates', cert, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();

        }
        return this.createTrackEvent(cert);


    }

    override async saveInSSLCertificate(cert: SSLCertificateEx) {
        this.isReady();
        this.config.inSSLCertificates = [];
        const crt = await this.rGetWith<SSLCertificateEx>('inSSLCertificates', cert.id);
        if (crt)
            this.config.inSSLCertificates.push(crt);

        let ret = await super.saveInSSLCertificate(cert);
        const pipeline = await this.redis.multi();
        await this.rSave('inSSLCertificates', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;

    }





    //TODO test
    override async getEmailSetting(): Promise<EmailSetting> {
        this.isReady();
        this.config.email = await this.rGet<EmailSetting>('email') || {
            type: 'empty',
            fromname: '', pass: '', user: ''
        };
        return await super.getEmailSetting();
    }

    override async setEmailSetting(options: EmailSetting) {
        this.isReady();
        this.config.email = await this.rGet<EmailSetting>('email') || {
            type: 'empty',
            fromname: '', pass: '', user: ''
        };
        const ret = await super.setEmailSetting(options);
        const pipeline = await this.redis.multi();
        await this.rSave('email', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    override async getLogo(): Promise<LogoSetting> {
        this.isReady();
        this.config.logo = await this.rGet<LogoSetting>('logo') || {};
        return await super.getLogo();
    }
    override async setLogo(logo: LogoSetting | {}) {
        this.isReady();
        this.config.logo = await this.rGet<LogoSetting>('email') || {};
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



    async setAuthSettingCommon(common: AuthCommon) {
        this.isReady();
        this.config.auth.common = await this.rGet<AuthCommon>('auth/common') || {};
        let ret = await super.setAuthSettingCommon(common);
        const pipeline = await this.redis.multi();
        await this.rSave('auth/common', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;


    }
    override async getAuthSettingCommon() {
        this.isReady();
        this.config.auth.common = await this.rGet<AuthCommon>('auth/common') || {};
        return super.getAuthSettingCommon();
    }

    override async setAuthSettingLocal(local: AuthLocal) {
        this.isReady();
        this.config.auth.local = await this.rGet<AuthLocal>('auth/local') || this.createAuthLocal();
        let ret = await super.setAuthSettingLocal(local);
        const pipeline = await this.redis.multi();
        await this.rSave('auth/local', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }
    override async getAuthSettingLocal() {
        this.isReady();
        this.config.auth.local = await this.rGet<AuthLocal>('auth/local') || this.createAuthLocal();
        return super.getAuthSettingLocal();
    }


    override async getAuthSettingOAuth() {
        this.isReady();
        this.config.auth.oauth = { providers: [] };
        this.config.auth.oauth.providers = await this.rGetAll<BaseOAuth>('auth/oauth/providers');
        return await super.getAuthSettingOAuth();
    }

    override async addAuthSettingOAuth(provider: BaseOAuth) {
        this.isReady();
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
        this.isReady();
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
        this.isReady();
        this.config.auth.ldap = { providers: [] };
        this.config.auth.ldap.providers = await this.rGetAll<BaseLdap>('auth/ldap/providers');
        return await super.getAuthSettingLdap();
    }

    override async addAuthSettingLdap(provider: BaseLdap) {
        this.isReady();
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
        this.isReady();
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
        this.isReady();
        this.config.auth.saml = { providers: [] };
        this.config.auth.saml.providers = await this.rGetAll<BaseSaml>('auth/saml/providers');
        return await super.getAuthSettingSaml();
    }

    override async addAuthSettingSaml(provider: BaseSaml) {
        this.isReady();
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
        this.isReady();
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
        this.isReady();
        this.config.networks = [];
        const network = await this.rGetWith<Network>(`networks`, id);
        if (network) {
            this.config.networks.push(network);
        }
        return await super.getNetwork(id);
    }
    override async getNetworkCount() {
        this.isReady();
        this.config.networks = [];
        return await this.rCount('networks/*');
    }

    override async getNetworkByName(name: string) {
        this.isReady();
        this.config.networks = await this.rGetAll('networks');
        return await super.getNetworkByName(name);
    }
    async getNetworkByGateway(gatewayId: string) {
        this.isReady();
        this.config.gateways = await this.rGetAll('gateways');
        this.config.networks = await this.rGetAll('networks');
        return await super.getNetworkByGateway(gatewayId);
    }

    async getNetworksBy(query: string) {
        this.isReady();
        this.config.networks = await this.rGetAll('networks');
        return await super.getNetworksBy(query);
    }
    async getNetworksAll() {
        this.isReady();
        this.config.networks = await this.rGetAll('networks');
        return await super.getNetworksAll();
    }

    async saveNetwork(network: Network) {
        this.isReady();
        this.config.networks = [];
        const net = await this.rGetWith<Network>('networks', network.id);
        if (net) this.config.networks.push(net);
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
            /*  const trc = this.createTrackEvent(previous, x);
             this.emitEvent({ type: "put", path: 'gateways', val: trc.after, before: trc.before }) */
        };

        //////////services

        let deleteServices = this.config.services.filter(x => x.networkId == net.id);
        this.config.services = this.config.services.filter(x => x.networkId != net.id);
        for (const x of deleteServices) {
            await this.rDel('services', x, pipeline);
            //const trc = this.createTrackEvent(x)
            //this.emitEvent({ type: 'del', path: 'services', val: trc.after, before: trc.before });
        }

        //// policy authorization
        let deleteAuthorizationRules = this.config.authorizationPolicy.rules.filter(x => x.networkId == net.id);
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => x.networkId != net.id);
        for (const x of deleteAuthorizationRules) {
            await this.rDel('authorizationPolicy/rules', x, pipeline);
            await this.rListDel('authorizationPolicy/rulesOrder', x.id, pipeline);
            //const trc = this.createTrackEvent(x);
            //this.emitEvent({ type: 'del', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before });
        };
        //check one more
        let deleteServicesId = deleteServices.map(x => x.id);
        let deleteAuthorizatonRules2 = this.config.authorizationPolicy.rules.filter(x => deleteServicesId.includes(x.serviceId));
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => !deleteServicesId.includes(x.serviceId));
        for (const x of deleteAuthorizatonRules2) {
            await this.rDel('authorizationPolicy/rules', x, pipeline);
            await this.rListDel('authorizationPolicy/rulesOrder', x.id, pipeline);
            //const trc = this.createTrackEvent(x);
            //this.emitEvent({ type: 'del', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before });
        }



        //policy authentication
        let deleteAuthenticationRules = this.config.authenticationPolicy.rules.filter(x => x.networkId == net.id);
        this.config.authenticationPolicy.rules = this.config.authenticationPolicy.rules.filter(x => x.networkId != net.id);
        for (const x of deleteAuthenticationRules) {
            await this.rDel('authenticationPolicy/rules', x, pipeline);
            await this.rListDel('authenticationPolicy/rulesOrder', x.id, pipeline);
            //const trc = this.createTrackEvent(x)
            //this.emitEvent({ type: 'del', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before });
        }


        // const trc = this.createTrackEvent(net)
        //this.emitEvent({ type: 'del', path: 'networks', val: trc.after, before: trc.before });

    }

    override async deleteNetwork(id: string) {
        this.isReady();

        this.config.networks = [];

        const network = await this.rGetWith<Network>('networks', id);
        if (network) {
            this.config.networks.push(network);
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
        this.isReady();
        this.config.domain = await this.rGet<string>('domain') || '';
        return await super.getDomain();
    }
    async setDomain(domain: string) {
        this.isReady();
        this.config.domain = await this.rGet<string>('domain') || '';
        const ret = await super.setDomain(domain);
        const pipeline = await this.redis.multi();
        await this.rSave('domain', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }


    override async getGateway(id: string) {
        this.isReady();
        this.config.gateways = [];

        const gateway = await this.rGetWith<Gateway>(`gateways`, id);
        if (gateway) {
            this.config.gateways.push(gateway)
        }
        return await super.getGateway(id);
    }
    override async getGatewayCount() {
        this.isReady();
        this.config.gateways = [];
        return await this.rCount('gateways/*')
    }

    override async getGatewaysByNetworkId(id: string) {
        this.isReady();
        this.config.gateways = await this.rGetAll('gateways');
        return await super.getGatewaysByNetworkId(id);
    }
    override async getGatewaysBy(query: string) {
        this.isReady();
        this.config.gateways = await this.rGetAll('gateways');
        return await super.getGatewaysBy(query);
    }

    override async getGatewaysAll() {
        this.isReady();
        this.config.gateways = await this.rGetAll('gateways');
        return await super.getGatewaysAll();
    }

    override async saveGateway(gateway: Gateway) {
        this.isReady();
        this.config.gateways = [];
        const gt = await this.rGetWith<Gateway>('gateways', gateway.id);
        if (gt) this.config.gateways.push(gt);
        let ret = await super.saveGateway(gateway);
        const pipeline = await this.redis.multi();
        await this.rSave('gateways', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }
    override async deleteGateway(id: string) {
        this.isReady();
        this.config.gateways = [];
        const gateway = await this.rGetWith<Gateway>('gateways', id);
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
        this.isReady();
        this.config.url = await this.rGet('url') || '';
        return super.getUrl();
    }
    override async setUrl(url: string) {
        this.isReady();
        this.config.url = await this.rGet('url') || '';
        let ret = await super.setUrl(url);
        const pipeline = await this.redis.multi();
        await this.rSave('url', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;

    }

    async getIsConfigured(): Promise<number> {
        this.isReady();
        this.config.isConfigured = await this.rGet('isConfigured') || 0;
        return await super.getIsConfigured();
    }

    async setIsConfigured(val: number) {
        this.isReady();
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
        this.isReady();
        this.config.groups = await this.rGetAll('groups');
        return await super.getGroup(id);

    }
    override async getGroupCount() {
        this.isReady();
        this.config.groups = [];
        return await this.rCount('groups/*');

    }

    override async getGroupsBySearch(query: string) {
        this.isReady();
        this.config.groups = await this.rGetAll('groups');
        return await super.getGroupsBySearch(query);
    }
    override async getGroupsAll() {
        this.isReady();
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

        /*  usersChanged.forEach(x => {
             const trc = this.createTrackEvent(x.previous, x.item);
             this.emitEvent({ type: 'put', path: 'users', val: trc.after, before: trc.before })
         })
 
         rulesAuthnChanged.forEach(x => {
             const trc = this.createTrackEvent(x.previous, x.item)
             this.emitEvent({ type: 'put', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before })
         })
 
         rulesAuthzChanged.forEach(x => {
             const trc = this.createTrackEvent(x.previous, x.item);
             this.emitEvent({ type: 'put', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before })
         })
 
 
         const trc = this.createTrackEvent(grp);
         this.emitEvent({ type: 'del', path: 'groups', val: trc.after, before: trc.before })
  */


    }

    override  async deleteGroup(id: string) {
        this.isReady();
        this.config.groups = [];
        const group = await this.rGetWith<Group>('groups', id);

        if (group) {
            this.config.groups.push(group);
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
        this.isReady();
        this.config.groups = [];
        const grp = await this.rGetWith<Group>('groups', group.id);
        if (grp)
            this.config.groups.push(grp);

        let ret = await super.saveGroup(group);
        const pipeline = await this.redis.multi();
        await this.rSave('groups', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;

    }


    override  async getService(id: string): Promise<Service | undefined> {
        this.isReady();
        this.config.services = await this.rGetAll('services');
        return await super.getService(id);

    }
    override async getServiceCount() {
        this.isReady();
        this.config.services = [];
        return await this.rCount('services/*');
    }

    override async getServicesBy(query?: string, networkIds?: string[], ids?: string[]) {
        this.isReady();
        this.config.services = await this.rGetAll('services');
        return await super.getServicesBy(query, networkIds, ids);
    }

    override async getServicesByNetworkId(networkId: string) {
        this.isReady();
        this.config.services = await this.rGetAll('services');
        return await super.getServicesByNetworkId(networkId);
    }

    //// service entity
    override async getServicesAll(): Promise<Service[]> {

        this.isReady();
        this.config.services = await this.rGetAll('services');
        return await super.getServicesAll();

    }


    async triggerServiceDeleted2(svc: Service, pipeline: RedisPipelineService) {

        //check authorization
        let rulesAuthzChanged = this.config.authorizationPolicy.rules.filter(x => x.serviceId == svc.id);
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => x.serviceId != svc.id);
        for (const x of rulesAuthzChanged) {
            await this.rDel('authorizationPolicy/rules', x, pipeline);
            await this.rListDel('authorizationPolicy/rulesOrder', x.id, pipeline);
            // const trc = this.createTrackEvent(x);
            // this.emitEvent({ type: 'del', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before })
        }

        //const trc = this.createTrackEvent(svc);
        //this.emitEvent({ type: 'del', path: 'services', val: trc.after, before: trc.before })

    }

    override async deleteService(id: string) {
        this.isReady();
        this.config.services = [];
        const svc = await this.rGetWith<Service>('services', id);
        if (svc) {
            this.config.services.push(svc);
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
        this.isReady();
        this.config.services = [];
        const svc = await this.rGetWith<Service>('services', service.id);
        if (svc) this.config.services.push(svc);
        let ret = await super.saveService(service);
        const pipeline = await this.redis.multi();
        await this.rSave('services', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }

    //authentication policy rule
    override async saveAuthenticationPolicyRule(arule: AuthenticationRule) {
        this.isReady();
        this.config.authenticationPolicy.rules = [];
        const rule = await this.rGetWith<AuthenticationRule>('authenticationPolicy/rules', arule.id)
        if (rule) this.config.authenticationPolicy.rules.push(rule);
        let ret = await super.saveAuthenticationPolicyRule(arule);
        const pipeline = await this.redis.multi();
        await this.rSave('authenticationPolicy/rules', ret.before, ret.after, pipeline);
        if (!ret.before && ret.after) {
            await this.rListAdd('authenticationPolicy/rulesOrder', ret.after.id, false, pipeline);
        }
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }
    override async getAuthenticationPolicy() {
        this.isReady();
        this.config.authenticationPolicy.rules = await this.rGetAll('authenticationPolicy/rules');
        this.config.authenticationPolicy.rulesOrder = await this.rListAll('authenticationPolicy/rulesOrder');
        return await super.getAuthenticationPolicy();
    }


    override async getAuthenticationPolicyRule(id: string) {
        this.isReady();
        this.config.authenticationPolicy.rules = [];
        const rule = await this.rGetWith<AuthenticationRule>('authenticationPolicy/rules', id);
        if (rule) this.config.authenticationPolicy.rules.push(rule);
        return await super.getAuthenticationPolicyRule(id);

    }
    override async getAuthenticationPolicyRuleCount() {
        this.isReady();
        return await this.rCount('authenticationPolicy/rules/*');

    }

    override async deleteAuthenticationPolicyRule(id: string) {
        this.isReady();
        this.config.authenticationPolicy.rules = [];


        const rule = await this.rGetWith<AuthenticationRule>('authenticationPolicy/rules', id)
        if (rule) {

            const pipeline = await this.redis.multi();
            await this.rDel('authenticationPolicy/rules', rule, pipeline);
            await this.rListDel('authenticationPolicy/rulesOrder', rule.id, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
            // const trc = this.createTrackEvent(rule);
            // this.emitEvent({ type: 'del', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before })


        }
        return this.createTrackEvent(rule);
    }

    //TODO remove these exceptions to REST API
    override  async updateAuthenticationRulePos(id: string, previous: number, next: string, index: number) {
        const currentRule = await this.rGetWith<AuthenticationRule>('authenticationPolicy/rules', id);
        if (!currentRule)
            throw new RestfullException(409, ErrorCodes.ErrConflictData, ErrorCodes.ErrConflictData, "no rule");

        const ruleId = await this.rListGetIndex<string>('authenticationPolicy/rulesOrder', previous);
        if (ruleId != id)
            throw new RestfullException(409, ErrorCodes.ErrConflictData, ErrorCodes.ErrConflictData, "no rule");
        const listlen = await this.rListLen('authenticationPolicy/rulesOrder');
        const pivot = await this.rListGetIndex('authenticationPolicy/rulesOrder', index);
        if (!pivot || next != pivot)
            throw new RestfullException(409, ErrorCodes.ErrConflictData, ErrorCodes.ErrConflictData, "no rule");

        const pipeline = await this.redis.multi();

        await this.rListDel('authenticationPolicy/rulesOrder', currentRule.id, pipeline);
        await this.rListInsert('authenticationPolicy/rulesOrder', id, previous < index ? 'AFTER' : 'BEFORE', pivot, previous, index, listlen, pipeline);

        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();

        //  const trc = this.createTrackIndexEvent(currentRule, previous, index);
        //  this.emitEvent({ type: 'put', path: 'authenticationPolicy/rulesOrder', val: trc.iAfter, before: trc.iBefore })

        return this.createTrackIndexEvent(currentRule, previous, index);


    }



    //authorization policy

    async saveAuthorizationPolicyRule(arule: AuthorizationRule) {
        this.isReady();
        this.config.authorizationPolicy.rules = [];

        const rule = await this.rGetWith<AuthorizationRule>('authorizationPolicy/rules', arule.id);
        if (rule)
            this.config.authorizationPolicy.rules.push(rule);

        let ret = await super.saveAuthorizationPolicyRule(arule);
        const pipeline = await this.redis.multi();
        await this.rSave('authorizationPolicy/rules', ret.before, ret.after, pipeline);
        if (!ret.before && ret.after) {
            await this.rListAdd('authorizationPolicy/rulesOrder', ret.after.id, false, pipeline);
        }
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;

    }
    async getAuthorizationPolicy() {
        this.isReady();
        this.config.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules');
        this.config.authorizationPolicy.rulesOrder = await this.rListAll('authorizationPolicy/rulesOrder');
        return await super.getAuthorizationPolicy();
    }

    async getAuthorizationPolicyRule(id: string) {
        this.isReady();
        this.config.authorizationPolicy.rules = [];
        const rule = await this.rGetWith<AuthorizationRule>('authorizationPolicy/rules', id);
        if (rule) this.config.authorizationPolicy.rules.push(rule);
        return await super.getAuthorizationPolicyRule(id);
    }

    async getAuthorizationPolicyRuleCount() {
        this.isReady();
        return await this.rCount('authorizationPolicy/rules/*');
    }
    async deleteAuthorizationPolicyRule(id: string) {
        this.isReady();
        this.config.authorizationPolicy.rules = [];

        const rule = await this.rGetWith<AuthorizationRule>('authorizationPolicy/rules', id);
        if (rule) {
            const pipeline = await this.redis.multi();
            await this.rDel('authorizationPolicy/rules', rule, pipeline);
            await this.rListDel('authorizationPolicy/rulesOrder', rule.id, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
            //const trc = this.createTrackEvent(rule);
            //this.emitEvent({ type: 'del', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before })


        }
        return this.createTrackEvent(rule);
    }

    //TODO remove these exceptions to REST API
    override  async updateAuthorizationRulePos(id: string, previous: number, next: string, index: number) {
        const currentRule = await this.rGetWith<AuthorizationRule>('authorizationPolicy/rules', id);
        if (!currentRule)
            throw new RestfullException(409, ErrorCodes.ErrConflictData, ErrorCodes.ErrConflictData, "no rule");

        const ruleId = await this.rListGetIndex<string>('authorizationPolicy/rulesOrder', previous);
        if (ruleId != id)
            throw new RestfullException(409, ErrorCodes.ErrConflictData, ErrorCodes.ErrConflictData, "no rule");
        const listlen = await this.rListLen('authorizationPolicy/rulesOrder');
        const pivot = await this.rListGetIndex('authorizationPolicy/rulesOrder', index);
        if (!pivot || pivot != next)
            throw new RestfullException(409, ErrorCodes.ErrConflictData, ErrorCodes.ErrConflictData, "no rule");
        const pipeline = await this.redis.multi();

        await this.rListDel('authorizationPolicy/rulesOrder', currentRule.id, pipeline);
        await this.rListInsert('authorizationPolicy/rulesOrder', id, previous < index ? 'AFTER' : 'BEFORE', pivot, previous, index, listlen, pipeline);

        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();

        //const trc = this.createTrackIndexEvent(currentRule, previous, index);
        //this.emitEvent({ type: 'put', path: 'authorizationPolicy/rules', val: trc.iAfter, before: trc.iBefore })

        return this.createTrackIndexEvent(currentRule, previous, index);


    }

    override async setES(conf: ESSetting): Promise<{ before?: ESSetting | undefined; after?: ESSetting | undefined; }> {
        this.isReady();
        this.config.es = await this.rGet<ESSetting>('es') || {};
        let ret = await super.setES(conf);
        const pipeline = await this.redis.multi();
        await this.rSave('es', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }
    override async getES(): Promise<ESSetting> {
        this.isReady();
        this.config.es = await this.rGet<ESSetting>('es') || {};
        return await super.getES();
    }


    /*
     * @summary export all config object
     * @param config 
     */
    override async getConfig(config?: Config) {
        const cfg = config || this.config;
        cfg.lastUpdateTime = await this.rGet('lastUpdateTime') || '';
        cfg.revision = await this.rGetDirect('revision') || 0;
        cfg.version = await this.rGet('version') || 0;
        cfg.isConfigured = await this.rGet('isConfigured') || 0;
        cfg.domain = await this.rGet('domain') || '';
        cfg.url = await this.rGet('url') || '';
        cfg.auth.common = await this.rGet('auth/common') || {};
        cfg.auth.local = await this.rGet('auth/local') || this.createAuthLocal();
        cfg.auth.ldap = {
            providers: await this.rGetAll('auth/ldap/providers')
        }
        cfg.auth.oauth = {
            providers: await this.rGetAll('auth/oauth/providers')
        }
        this.config.auth.saml = {
            providers: await this.rGetAll('auth/saml/providers')
        }
        cfg.jwtSSLCertificate = await this.rGet('jwtSSLCertificate') || {
            idEx: Util.randomNumberString(16),
            name: 'JWT',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            labels: [], isEnabled: true, category: 'jwt',
            usages: []
        };
        cfg.webSSLCertificate = await this.rGet('webSSLCertificate') || {
            idEx: Util.randomNumberString(16),
            name: 'SSL',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            labels: [], isEnabled: true, category: 'web',
            usages: []
        };
        cfg.caSSLCertificate = await this.rGet('caSSLCertificate') || {
            idEx: Util.randomNumberString(16),
            name: 'CA',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            labels: [], isEnabled: true, category: 'ca',
            usages: []
        };
        cfg.inSSLCertificates = await this.rGetAll('inSSLCertificates');
        cfg.users = await this.rGetAll('users');
        cfg.groups = await this.rGetAll('groups');
        cfg.services = await this.rGetAll('services');
        cfg.captcha = await this.rGet('captcha') || {};
        cfg.email = await this.rGet('email') || this.createDefaultEmail();
        cfg.logo = await this.rGet('logo') || {};
        cfg.networks = await this.rGetAll('networks');
        cfg.gateways = await this.rGetAll('gateways');
        cfg.authenticationPolicy.rules = await this.rGetAll('authenticationPolicy/rules');
        cfg.authenticationPolicy.rulesOrder = await this.rListAll('authenticationPolicy/rulesOrder');
        cfg.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules');
        cfg.authorizationPolicy.rulesOrder = await this.rListAll('authorizationPolicy/rulesOrder');
        cfg.es = await this.rGet('es') || {};



        cfg.ipIntelligence.sources = await this.rGetAll('ipIntelligence/sources');
        cfg.ipIntelligence.lists = await this.rGetAll('ipIntelligence/lists');

    }

    /**
     * @summary import all config
     * @param cfg 
     */
    override async setConfig(cfg: Config) {
        const pipeline = await this.redis.multi();
        await this.rFlushAll(pipeline);
        await this.rSave('version', undefined, cfg.version, pipeline);
        await this.rSave('isConfigured', undefined, cfg.isConfigured, pipeline);
        await this.rSave('revision', undefined, cfg.revision, pipeline);
        await this.rSaveArray('users', cfg.users, pipeline,
            async (before: any, data: any, trx: RedisPipelineService) => {
                await this.saveUserIndexes(data, trx);
                return data;
            });
        await this.rSaveArray('groups', cfg.groups, pipeline);
        await this.rSaveArray('services', cfg.services, pipeline);
        await this.rSave('captcha', undefined, cfg.captcha, pipeline);
        await this.rSave('jwtSSLCertificate', undefined, cfg.jwtSSLCertificate, pipeline);
        await this.rSave('webSSLCertificate', undefined, cfg.webSSLCertificate, pipeline);
        await this.rSave('caSSLCertificate', undefined, cfg.caSSLCertificate, pipeline);
        await this.rSaveArray('inSSLCertificates', cfg.inSSLCertificates, pipeline);
        await this.rSave('domain', undefined, cfg.domain, pipeline);
        await this.rSave('url', undefined, cfg.url, pipeline);
        await this.rSave('email', undefined, cfg.email, pipeline);
        await this.rSave('logo', undefined, cfg.logo, pipeline);
        await this.rSave('auth/common', undefined, cfg.auth.common, pipeline);
        await this.rSave('auth/local', undefined, cfg.auth.local, pipeline);
        await this.rSaveArray('auth/ldap/providers', cfg.auth.ldap?.providers || [], pipeline);
        await this.rSaveArray('auth/oauth/providers', cfg.auth.oauth?.providers || [], pipeline);
        await this.rSaveArray('auth/saml/providers', cfg.auth.saml?.providers || [], pipeline);
        await this.rSaveArray('networks', cfg.networks, pipeline);
        await this.rSaveArray('gateways', cfg.gateways, pipeline);
        await this.rSaveArray('authenticationPolicy/rules', cfg.authenticationPolicy.rules, pipeline);
        for (const order of cfg.authenticationPolicy.rulesOrder) {
            await this.rListAdd('authenticationPolicy/rulesOrder', order, true, pipeline);
        }
        await this.rSaveArray('authorizationPolicy/rules', cfg.authorizationPolicy.rules, pipeline);
        for (const order of cfg.authorizationPolicy.rulesOrder) {
            await this.rListAdd('authorizationPolicy/rulesOrder', order, true, pipeline);
        }
        await this.rSave('lastUpdateTime', undefined, cfg.lastUpdateTime, pipeline);
        await this.rSave('es', undefined, cfg.es, pipeline);


        await this.rSaveArray('ipIntelligence/sources', cfg.ipIntelligence.sources, pipeline);
        await this.rSaveArray('ipIntelligence/lists', cfg.ipIntelligence.lists, pipeline);


        await pipeline.exec();
        this.config = this.createConfig();

    }

    /////////////////// ip intelligence /////////////////////////////



    override async getIpIntelligenceSources(): Promise<IpIntelligenceSource[]> {
        this.isReady();
        this.config.ipIntelligence.sources = await this.rGetAll('ipIntelligence/sources');
        return await super.getIpIntelligenceSources();
    }
    override async getIpIntelligenceSource(id: string) {
        this.isReady();
        this.config.ipIntelligence.sources = [];
        const src = await this.rGetWith<IpIntelligenceSource>(`ipIntelligence/sources`, id);
        if (src) {
            this.config.ipIntelligence.sources.push(src);
        }
        return await super.getIpIntelligenceSource(id);
    }

    async saveIpIntelligenceSource(source: IpIntelligenceSource) {
        this.isReady();
        this.config.ipIntelligence.sources = [];
        const src = await this.rGetWith<IpIntelligenceSource>('ipIntelligence/sources', source.id);
        if (src) this.config.ipIntelligence.sources.push(src);
        let ret = await super.saveIpIntelligenceSource(source);
        const pipeline = await this.redis.multi();
        await this.rSave('ipIntelligence/sources', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }
    async deleteIpIntelligenceSource(id: string) {
        this.isReady();

        this.config.ipIntelligence.sources = [];

        const source = await this.rGetWith<IpIntelligenceSource>('ipIntelligence/sources', id);
        if (source) {
            this.config.ipIntelligence.sources.push(source);
            const pipeline = await this.redis.multi();
            await this.rDel('ipIntelligence/sources', source, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
        }
        return this.createTrackEvent(source)
    }


    override async getIpIntelligenceLists(): Promise<IpIntelligenceList[]> {
        this.isReady();
        this.config.ipIntelligence.lists = await this.rGetAll('ipIntelligence/lists');
        return await super.getIpIntelligenceLists();
    }
    override async getIpIntelligenceList(id: string) {
        this.isReady();
        this.config.ipIntelligence.lists = [];
        const src = await this.rGetWith<IpIntelligenceList>(`ipIntelligence/lists`, id);
        if (src) {
            this.config.ipIntelligence.lists.push(src);
        }
        return await super.getIpIntelligenceList(id);
    }

    async saveIpIntelligenceList(list: IpIntelligenceList) {
        this.isReady();
        this.config.ipIntelligence.lists = [];
        const src = await this.rGetWith<IpIntelligenceList>('ipIntelligence/lists', list.id);
        if (src) this.config.ipIntelligence.lists.push(src);
        let ret = await super.saveIpIntelligenceList(list);
        const pipeline = await this.redis.multi();
        await this.rSave('ipIntelligence/lists', ret.before, ret.after, pipeline);
        await this.saveLastUpdateTime(pipeline);
        await pipeline.exec();
        return ret;
    }
    async triggerIpIntelligenceListDeleted(list: IpIntelligenceList, pipeline: RedisPipelineService) {
        //await this.rSave('authenticationPolicy/rules', ret.before, ret.after, pipeline);

        for (const it of this.config.authenticationPolicy.rules) {
            let before = null;
            let changed = false;
            if (it.profile.ipIntelligence?.blackLists.includes(list.id)) {
                before = Util.clone(it);
                it.profile.ipIntelligence.blackLists = it.profile.ipIntelligence.blackLists.filter(x => list.id != x);
                changed = true;
            }
            if (it.profile.ipIntelligence?.whiteLists.includes(list.id)) {
                if (!before)
                    before = Util.clone(it);
                it.profile.ipIntelligence.whiteLists = it.profile.ipIntelligence.whiteLists.filter(x => list.id != x);
                changed = true;
            }
            if (changed) {
                await this.rSave('authenticationPolicy/rules', before, it, pipeline);
            }
        }
    }

    async deleteIpIntelligenceList(id: string) {
        this.isReady();

        this.config.ipIntelligence.lists = [];

        const list = await this.rGetWith<IpIntelligenceList>('ipIntelligence/lists', id);
        if (list) {
            this.config.ipIntelligence.lists.push(list);
            this.config.authenticationPolicy = await this.getAuthenticationPolicy();
            const pipeline = await this.redis.multi();
            await this.triggerIpIntelligenceListDeleted(list, pipeline);
            await this.rDel('ipIntelligence/lists', list, pipeline);
            await this.saveLastUpdateTime(pipeline);
            await pipeline.exec();
        }
        return this.createTrackEvent(list);
    }






}


class NodeCacheForUs extends NodeCache {
    override get<T>(key: RPath): T | undefined {
        return super.get<T>(key);
    }

    override set<T>(key: RPath, value: T): boolean {
        return super.set(key, value);
    }

}

export class RedisCachedConfigService extends RedisConfigService {
    nodeCache = new NodeCacheForUs(
        {
            deleteOnExpire: true, stdTTL: 60 * 60, useClones: false
        }
    )

    protected override async afterInit(): Promise<void> {
        await this.logWatcher.watcher.events.on('data', async (data: WatchItem<ConfigWatch<any>>) => {
            logger.info(`system changed log received ${data.val.path}`);
            await this.execute(data);
        })

        await this.logWatcher.startWatch();
    }

    //below cache items must follow and clear cache
    async execute(watch: WatchItem<ConfigWatch<any>>) {
        try {
            const item = watch.val;
            let rpath = item.path;
            if (rpath.startsWith('/config')) {
                let path = rpath.substring(8) as RPath;
                let val = item.val;
                let type = item.type;

                switch (path) {
                    case 'jwtSSLCertificate':
                        this.nodeCache.del('jwtSSLCertificate');
                        break;
                    case 'captcha':
                        this.nodeCache.del('captcha');
                        break;
                    case 'domain':
                        this.nodeCache.del('domain');
                        break;
                    case 'url':
                        this.nodeCache.del('url');
                        break;
                    case 'es':
                        this.nodeCache.del('es');
                        break;
                    case 'caSSLCertificate':
                        this.nodeCache.del('caSSLCertificate');
                        break;
                    default:
                        logger.warn(`not implemented path ${item.path}`)
                }
                logger.info(`config changed ${watch.val.path} -> ${watch.val.type} id:${watch.val.val?.id || 'unknown'}`)

                this.events.emit('configChanged', watch.val);
                this.events.emit('log', watch);


            } else {
                this.events.emit('data', watch);
                this.events.emit('log', watch);
            }

        } catch (err) {
            logger.error(err);
        }
    }

    override async getJWTSSLCertificate(): Promise<SSLCertificate> {
        const ssl = this.nodeCache.get<SSLCertificate>('jwtSSLCertificate');
        if (ssl) return ssl;
        const sup = await super.getJWTSSLCertificate();
        this.nodeCache.set('jwtSSLCertificate', sup);
        return sup;
    }

    override async setJWTSSLCertificate(cert: SSLCertificate | {}) {

        const ret = await super.setJWTSSLCertificate(cert);
        this.nodeCache.set('jwtSSLCertificate', ret.after);
        return ret;
    }

    override async getCaptcha(): Promise<Captcha> {
        const val = this.nodeCache.get<Captcha>('captcha');
        if (val) return val;
        const sup = await super.getCaptcha();
        this.nodeCache.set('captcha', sup);
        return sup;
    }

    override async setCaptcha(captcha: Captcha | {}) {
        const ret = await super.setCaptcha(captcha);
        this.nodeCache.set('captcha', ret.after);
        return ret;
    }

    override async getDomain(): Promise<string> {
        const val = this.nodeCache.get<string>('domain');
        if (val) return val;
        const sup = await super.getDomain();
        this.nodeCache.set('domain', sup);
        return sup;
    }

    override async setDomain(domain: string) {
        const ret = await super.setDomain(domain);
        this.nodeCache.set('domain', ret.after);
        return ret;
    }

    override async getUrl(): Promise<string> {
        const val = this.nodeCache.get<string>('url');
        if (val) return val;
        const sup = await super.getUrl();
        this.nodeCache.set('url', sup);
        return sup;
    }

    override async setUrl(url: string) {
        const ret = await super.setUrl(url);
        this.nodeCache.set('url', ret.after);
        return ret;
    }

    override async setES(conf: ESSetting): Promise<{ before?: ESSetting | undefined; after?: ESSetting | undefined; }> {
        const ret = await super.setES(conf);
        this.nodeCache.set('es', ret.after);
        return ret;
    }
    override async getES(): Promise<ESSetting> {
        const val = this.nodeCache.get<ESSetting>('es');
        if (val) return val;
        const sup = await super.getES();
        this.nodeCache.set('es', sup);
        return sup;
    }
    override async setCASSLCertificate(cert: {} | SSLCertificate): Promise<{ before?: SSLCertificate | undefined; after?: SSLCertificate | undefined; }> {
        const ret = await super.setCASSLCertificate(cert);
        this.nodeCache.set('caSSLCertificate', ret.after);
        return ret;
    }
    override async getCASSLCertificate(): Promise<SSLCertificate> {
        const val = this.nodeCache.get<SSLCertificate>('caSSLCertificate');
        if (val) return val;
        const sup = await super.getCASSLCertificate()
        this.nodeCache.set("caSSLCertificate", sup);
        return sup;
    }






}
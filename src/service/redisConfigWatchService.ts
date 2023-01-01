import { Util } from "../util";
import { logger } from "../common";
import { ConfigService } from "./configService";
import { RedisPipelineService, RedisService } from "./redisService";
import { User } from "../model/user";
import { WatchItem, WatchService } from "./watchService";
import { EventEmitter, pipeline } from "stream";
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
import NodeCache from "node-cache";
import { RestfullException } from "../restfullException";
import { ErrorCodes } from "../restfullException";
import { ConfigEvent } from "../model/config";
import { ConfigWatch, RedisConfigService, RPath } from "./redisConfigService";

const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export interface ItemWithId {
    id: string;
    [key: string]: any;
}


export class RedisConfigWatchService extends ConfigService {

    executeList: WatchItem<ConfigWatch<any>>[] = [];
    watch: EventEmitter = new EventEmitter();
    interval: any;
    redisConfig: RedisConfigService;
    isFilled = false;
    constructor(private redis: RedisService, private redisStream: RedisService,
        encryptKey: string, uniqueName = 'redisconfig', configFile?: string) {
        super(encryptKey, configFile);
        this.redisConfig = new RedisConfigService(this.redis, this.redisStream, encryptKey, uniqueName, configFile);

    }


    override async start(): Promise<void> {

        await this.redisConfig.logWatcher.events.on('data', (data: WatchItem<ConfigWatch<any>>) => {
            this.executeList.push(data);
        })
        await this.redisConfig.logWatcher.startWatch();
        this.interval = await setIntervalAsync(async () => {
            await this.processExecuteList();
        }, 1000);

    }
    override async stop(): Promise<void> {
        await this.redisConfig.logWatcher.stopWatch();
        if (this.interval)
            clearIntervalAsync(this.interval);
        this.interval = null;

    }
    override emitEvent(event: ConfigEvent): void {

    }
    override isReady(): void {
        if (!this.isFilled) {
            throw new RestfullException(412, ErrorCodes.ErrSystemIsNotReady, ErrorCodes.ErrSystemIsNotReady, 'config is not ready');

        }
    }
    override isWritable(): void {
        throw new RestfullException(405, ErrorCodes.ErrMethodNotAllowed, ErrorCodes.ErrMethodNotAllowed, 'config is writable');
    }

    async fillFromRedis(): Promise<void> {

        if (this.isFilled) return;
        console.log('filling from redis');
        this.config.lastUpdateTime = await this.redisConfig.rGet('lastUpdateTime') || '';
        this.config.revision = await this.redisConfig.rGetDirect('revision');
        this.config.version = await this.redisConfig.rGet('version') || 0;
        this.config.isConfigured = await this.redisConfig.rGet('isConfigured') || 0;
        this.config.domain = await this.redisConfig.rGet('domain') || '';
        this.config.url = await this.redisConfig.rGet('url') || '';
        this.config.auth.common = await this.redisConfig.rGet('auth/common') || {};
        this.config.auth.local = await this.redisConfig.rGet('auth/local') || this.createAuthLocal();
        this.config.auth.ldap = {
            providers: await this.redisConfig.rGetAll('auth/ldap/providers')
        }
        this.config.auth.oauth = {
            providers: await this.redisConfig.rGetAll('auth/oauth/providers')
        }
        this.config.auth.saml = {
            providers: await this.redisConfig.rGetAll('auth/saml/providers')
        }
        this.config.jwtSSLCertificate = await this.redisConfig.rGet('jwtSSLCertificate') || {};
        this.config.sslCertificate = await this.redisConfig.rGet('sslCertificate') || {};
        this.config.caSSLCertificate = await this.redisConfig.rGet('caSSLCertificate') || {};
        this.config.users = await this.redisConfig.rGetAll('users');
        this.config.groups = await this.redisConfig.rGetAll('groups');
        this.config.services = await this.redisConfig.rGetAll('services');
        this.config.captcha = await this.redisConfig.rGet('captcha') || {};
        this.config.email = await this.redisConfig.rGet('email') || this.createDefaultEmail();
        this.config.logo = await this.redisConfig.rGet('logo') || {};
        this.config.networks = await this.redisConfig.rGetAll('networks');
        this.config.gateways = await this.redisConfig.rGetAll('gateways');
        this.config.authenticationPolicy.rules = await this.redisConfig.rGetAll('authenticationPolicy/rules');
        this.config.authenticationPolicy.rulesOrder = await this.redisConfig.rListAll('authenticationPolicy/rulesOrder');
        this.config.authorizationPolicy.rules = await this.redisConfig.rGetAll('authorizationPolicy/rules');
        this.config.authorizationPolicy.rulesOrder = await this.redisConfig.rListAll('authorizationPolicy/rulesOrder');
        this.isFilled = true;
        console.log('is filled');

    }
    /*  protected findParts(path: string) {
 
 
 
         const list1: RPath[] = ['authenticationPolicy/rulesOrder', 'authorizationPolicy/rulesOrder'];
         for (const item of list1) {
             if (path.startsWith(`/config/${item}`)) {
                 //let id = path.replace('/config', '').replace(item, '').replace('/', '');
                 return { path: item, id: undefined };
             }
         }
         const list2: RPath[] = ['users', 'groups', 'services', 'networks',
             'gateways', 'authenticationPolicy/rules', 'authorizationPolicy/rules',
             'auth/ldap/providers', 'auth/oauth/providers', 'auth/saml/providers']
 
         for (const item of list2) {
             if (path.startsWith(`/config/${item}`)) {
                 let id = path.replace('/config', '').replace(item, '').replace('/', '');
                 return { path: item, id: id };
             }
         }
 
         const list3: RPath[] = ['lastUpdateTime', 'revision', 'version', 'isConfigured', 'domain',
             'url', 'jwtSSLCertificate', 'sslCertificate', 'caSSLCertificate', 'captcha', 'email', 'logo',
             'auth/common', 'auth/local']
 
         for (const item of list3) {
             if (path.startsWith(`/config/${item}`)) {
                 let id = path.replace('/config', '').replace(item, '').replace('/', '');
                 return { path: item, id: id };
             }
         }
 
 
         throw new Error(`not implemented path ${path}`)
     } */
    async removeFromArray(arr: ItemWithId[], id: string) {
        let index = arr.findIndex(x => x.id == id)
        if (index >= 0) {
            arr.splice(index, 1);
        }
    }
    async saveToArray(arr: ItemWithId[], item: ItemWithId) {
        let index = arr?.findIndex(x => x.id == item.id)
        if (index >= 0) {
            arr[index] = item;
        }
        else arr.push(item);
    }
    async processArray(arr: ItemWithId[], path: RPath, item: ConfigWatch<any>, id?: string) {
        if (item.type == 'del' && id) {
            this.removeFromArray(arr, id);

        }
        if (item.type == 'put' && id) {
            this.saveToArray(arr, item.val);

        }
    }


    async processExecuteList() {
        try {
            await this.fillFromRedis();
            if (!this.config.auth.ldap)
                this.config.auth.ldap = { providers: [] };
            if (!this.config.auth.oauth)
                this.config.auth.oauth = { providers: [] };
            if (!this.config.auth.saml)
                this.config.auth.saml = { providers: [] };
            while (this.executeList.length) {
                const item = this.executeList[0].val;
                let rpath = item.path;
                let path = rpath.startsWith('/config/') ? rpath.substring(8) : rpath;
                let val = item.val;
                let type = item.type;

                switch (path) {
                    case 'lastUpdateTime':
                        this.config.lastUpdateTime = await this.redisConfig.rGet(path) || '';
                        break;
                    case 'revision':
                        this.config.revision = await this.redisConfig.rGetDirect(path);
                        break;
                    case 'version':
                        this.config.version = await this.redisConfig.rGet(path) || 0;
                        break;
                    case 'isConfigured':
                        this.config.isConfigured = await this.redisConfig.rGet(path) || 0;
                        break;
                    case 'domain':
                        this.config.domain = await this.redisConfig.rGet(path) || '';
                        break;
                    case 'url':
                        this.config.url = await this.redisConfig.rGet(path) || '';
                        break;
                    case 'auth/common':
                        this.config.auth.common = await this.redisConfig.rGet(path) || {};
                        break;
                    case 'auth/local':
                        this.config.auth.local = await this.redisConfig.rGet(path) || this.createAuthLocal();
                        break;
                    case 'auth/ldap/providers':
                        await this.processArray(this.config.auth.ldap.providers, path, item, val.id);
                        break;
                    case 'auth/oauth/providers':
                        await this.processArray(this.config.auth.oauth.providers, path, item, val.id);
                        break;
                    case 'auth/saml/providers':
                        await this.processArray(this.config.auth.saml.providers, path, item, val.id);
                        break;
                    case 'jwtSSLCertificate':
                        this.config.jwtSSLCertificate = await this.redisConfig.rGet(path) || {};
                        break;
                    case 'sslCertificate':
                        this.config.sslCertificate = await this.redisConfig.rGet(path) || {};
                        break;
                    case 'caSSLCertificate':
                        this.config.caSSLCertificate = await this.redisConfig.rGet(path) || {};
                        break;
                    case 'users':
                        await this.processArray(this.config.auth.ldap.providers, path, item, val.id);
                        break;
                    case 'groups':
                        await this.processArray(this.config.auth.ldap.providers, path, item, val.id);
                        break;
                    case 'services':
                        await this.processArray(this.config.auth.ldap.providers, path, item, val.id);
                        break;
                    case 'captcha':
                        this.config.captcha = await this.redisConfig.rGet(path) || {};
                        break;
                    case 'email':
                        this.config.email = await this.redisConfig.rGet(path) || this.createDefaultEmail();
                        break;
                    case 'logo':
                        this.config.logo = await this.redisConfig.rGet(path) || {};
                        break;
                    case 'networks':
                        await this.processArray(this.config.auth.ldap.providers, path, item, val.id);
                        break;
                    case 'gateways':
                        await this.processArray(this.config.auth.ldap.providers, path, item, val.id);
                        break;
                    case 'authenticationPolicy/rules':
                        await this.processArray(this.config.auth.ldap.providers, path, item, val.id);
                        break;
                    case 'authenticationPolicy/rulesOrder':
                        this.config.authenticationPolicy.rulesOrder = await this.redisConfig.rListAll('authenticationPolicy/rulesOrder');
                        break;
                    case 'authorizationPolicy/rules':
                        await this.processArray(this.config.auth.ldap.providers, path, item, val.id);
                        break;
                    case 'authorizationPolicy/rulesOrder':
                        this.config.authorizationPolicy.rulesOrder = await this.redisConfig.rListAll('authorizationPolicy/rulesOrder');
                        break;
                    default:
                        throw new Error(`not implemented path ${item.path}`)
                }
                this.executeList.shift();
                this.watch.emit('configChanged', item);
            }


        } catch (err) {
            logger.error(err);
        }
    }



}



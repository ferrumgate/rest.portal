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


export class RedisConfigWatchService extends RedisConfigService {

    executeList: WatchItem<ConfigWatch<any>>[] = [];
    watch: EventEmitter = new EventEmitter();
    interval: any;
    override async start(): Promise<void> {
        await super.start();
        await this.logWatcher.events.on('data', (data: WatchItem<ConfigWatch<any>>) => {
            this.executeList.push(data);
        })
        await this.logWatcher.startWatch();
        this.interval = await setIntervalAsync(async () => {
            await this.processExecuteList();
        }, 1000);

    }
    override async stop(): Promise<void> {
        await super.stop();
        await this.logWatcher.stopWatch();
    }
    override emitEvent(event: ConfigEvent): void {

    }

    override async afterInit(): Promise<void> {
        this.config.lastUpdateTime = await this.rGet('lastUpdateTime') || '';
        this.config.revision = await this.rGetDirect('revision');
        this.config.version = await this.rGet('version') || 0;
        this.config.isConfigured = await this.rGet('isConfigured') || 0;
        this.config.domain = await this.rGet('domain') || '';
        this.config.url = await this.rGet('url') || '';
        this.config.auth.common = await this.rGet('auth/common') || {};
        this.config.auth.local = await this.rGet('auth/local') || this.createAuthLocal();
        this.config.auth.ldap = {
            providers: await this.rGetAll('auth/ldap/providers')
        }
        this.config.auth.oauth = {
            providers: await this.rGetAll('auth/oauth/providers')
        }
        this.config.auth.saml = {
            providers: await this.rGetAll('auth/saml/providers')
        }
        this.config.jwtSSLCertificate = await this.rGet('jwtSSLCertificate') || {};
        this.config.sslCertificate = await this.rGet('sslCertificate') || {};
        this.config.caSSLCertificate = await this.rGet('caSSLCertificate') || {};
        this.config.users = await this.rGetAll('users');
        this.config.groups = await this.rGetAll('groups');
        this.config.services = await this.rGetAll('services');
        this.config.captcha = await this.rGet('captcha') || {};
        this.config.email = await this.rGet('email') || this.createDefaultEmail();
        this.config.logo = await this.rGet('logo') || {};
        this.config.networks = await this.rGetAll('networks');
        this.config.gateways = await this.rGetAll('gateways');
        this.config.authenticationPolicy.rules = await this.rGetAll('authenticationPolicy/rules');
        this.config.authenticationPolicy.rulesOrder = await this.rListAll('authenticationPolicy/rulesOrder');
        this.config.authorizationPolicy.rules = await this.rGetAll('authorizationPolicy/rules');
        this.config.authorizationPolicy.rulesOrder = await this.rListAll('authorizationPolicy/rulesOrder');


    }
    protected findParts(path: string) {
        const list: RPath[] = ['users', 'groups', 'services', 'networks', 'gateways',
        ]

        for (const item of list) {
            if (path.startsWith(`/config/${item}`)) {
                let id = path.replace(item, '').replace('/', '');
                return { path: item, id: id };
            }
        }


        const list2: RPath[] = ['authenticationPolicy/rulesOrder', 'authorizationPolicy/rulesOrder'];
        for (const item of list2) {
            if (path.startsWith(`/config/${item}`)) {
                let id = path.replace(item, '').replace('/', '');
                return { path: item, id: id };
            }
        }
        const list3: RPath[] = ['authenticationPolicy/rules', 'authorizationPolicy/rules'];
        for (const item of list3) {
            if (path.startsWith(`/config/${item}`)) {
                let id = path.replace(item, '').replace('/', '') as string;
                return { path: item, id: id };
            }
        }
        return { path: undefined, id: undefined };
    }
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
            if (!this.config.auth.ldap)
                this.config.auth.ldap = { providers: [] };
            if (!this.config.auth.oauth)
                this.config.auth.oauth = { providers: [] };
            if (!this.config.auth.saml)
                this.config.auth.saml = { providers: [] };
            while (this.executeList.length) {
                const item = this.executeList[0].val;
                let { path, id } = this.findParts(item.path);
                let val = item.val;
                let type = item.type;
                switch (path) {
                    case 'lastUpdateTime':
                        this.config.lastUpdateTime = await this.rGet(path) || '';
                        break;
                    case 'revision':
                        this.config.revision = await this.rGetDirect(path);

                        break;
                    case 'version':
                        this.config.version = await this.rGet(path) || 0;

                        break;
                    case 'isConfigured':
                        this.config.isConfigured = await this.rGet(path) || 0;
                        break;
                    case 'domain':
                        this.config.domain = await this.rGet(path) || '';
                        break;
                    case 'url':
                        this.config.url = await this.rGet(path) || '';
                        break;
                    case 'auth/common':
                        this.config.auth.common = await this.rGet(path) || {};

                        break;
                    case 'auth/ldap/providers':
                        await this.processArray(this.config.auth.ldap.providers, path, item, id);
                        break;
                    case 'auth/oauth/providers':
                        await this.processArray(this.config.auth.oauth.providers, path, item, id);

                        break;
                    case 'auth/saml/providers':
                        await this.processArray(this.config.auth.saml.providers, path, item, id);
                        break;
                    case 'jwtSSLCertificate':
                        this.config.jwtSSLCertificate = await this.rGet(path) || {};
                        break;
                    case 'sslCertificate':
                        this.config.sslCertificate = await this.rGet(path) || {};
                        break;
                    case 'caSSLCertificate':
                        this.config.caSSLCertificate = await this.rGet(path) || {};
                        break;
                    case 'users':
                        await this.processArray(this.config.auth.ldap.providers, path, item, id);
                        break;
                    case 'groups':
                        await this.processArray(this.config.auth.ldap.providers, path, item, id);
                        break;
                    case 'services':
                        await this.processArray(this.config.auth.ldap.providers, path, item, id);
                        break;
                    case 'captcha':
                        this.config.captcha = await this.rGet(path) || {};
                        break;
                    case 'email':
                        this.config.email = await this.rGet(path) || this.createDefaultEmail();
                        break;
                    case 'logo':
                        this.config.logo = await this.rGet(path) || {};
                        break;
                    case 'networks':
                        await this.processArray(this.config.auth.ldap.providers, path, item, id);
                        break;
                    case 'gateways':
                        await this.processArray(this.config.auth.ldap.providers, path, item, id);
                        break;
                    case 'authenticationPolicy/rules':
                        await this.processArray(this.config.auth.ldap.providers, path, item, id);
                        break;
                    case 'authenticationPolicy/rulesOrder':
                        this.config.authenticationPolicy.rulesOrder = await this.rListAll('authenticationPolicy/rulesOrder');
                        break;
                    case 'authorizationPolicy/rules':
                        await this.processArray(this.config.auth.ldap.providers, path, item, id);
                        break;
                    case 'authorizationPolicy/rulesOrder':
                        this.config.authorizationPolicy.rulesOrder = await this.rListAll('authorizationPolicy/rulesOrder');
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



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
import { SSLCertificate } from "../model/cert";
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
import { RedisConfigService } from "./redisConfigService";
import { SystemLogService } from "./systemLogService";
import { ConfigWatch, RPath } from "../model/config";



const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export interface ItemWithId {
    id: string;
    [key: string]: any;
}

/**
 * @summary this is config watcher, that fills config from redis, and follows a change log, and refreshs config
 * @readonly
 */
export class RedisConfigWatchService extends ConfigService {

    executeList: WatchItem<ConfigWatch<any>>[] = [];
    //watch: EventEmitter = new EventEmitter();
    interval: any;
    redisConfig: RedisConfigService;
    isFilled = false;
    isStable = true;
    constructor(private redis: RedisService, private redisStream: RedisService,
        systemlog: SystemLogService,
        private followSystemLog: boolean,
        encryptKey: string, uniqueName = 'redisconfig',
        configFile?: string, logReadWaitMS = 1000) {
        super(encryptKey, configFile);
        this.redisConfig = new RedisConfigService(this.redis, this.redisStream, systemlog, encryptKey, uniqueName, configFile, logReadWaitMS);

    }



    /**
     * @summary stars log watching and execute config changes
     */
    override async start(): Promise<void> {
        if (this.followSystemLog) {
            await this.redisConfig.systemLogWatcher.watcher.events.on('data', (data: WatchItem<ConfigWatch<any>>) => {
                this.executeList.push(data);
            })

            await this.redisConfig.systemLogWatcher.startWatch();
        }
        else {
            await this.redisConfig.logWatcher.watcher.events.on('data', (data: WatchItem<ConfigWatch<any>>) => {
                this.executeList.push(data);
            })

            await this.redisConfig.logWatcher.startWatch();
        }
        this.interval = setIntervalAsync(async () => {
            await this.processExecuteList();
        }, 500);

    }
    /**
     * @summary stop log watching, and stop config change
     */
    override async stop(): Promise<void> {
        await this.redisConfig.systemLogWatcher.watcher.stopWatch();
        await this.redisConfig.logWatcher.stopWatch();
        if (this.interval)
            clearIntervalAsync(this.interval);
        this.interval = null;

    }
    override publishEvent(ev: string, data?: any): void {

    }
    override emitEvent<T>(event: ConfigWatch<T>): void {

    }
    override isReady(): void {
        if (!this.isFilled) {
            throw new RestfullException(412, ErrorCodes.ErrSystemIsNotReady, ErrorCodes.ErrSystemIsNotReady, 'config is not ready');
        }
        if (!this.isStable) {
            throw new RestfullException(412, ErrorCodes.ErrSystemIsNotReady, ErrorCodes.ErrSystemIsNotReady, 'config is not stable');
        }
    }
    override isWritable(): void {
        throw new RestfullException(405, ErrorCodes.ErrMethodNotAllowed, ErrorCodes.ErrMethodNotAllowed, 'config is writable');
    }
    override clone<T>(data: T): T {
        return data;
    }
    override loadConfigFromFile(): void {

    }
    override async saveConfigToFile(): Promise<void> {

    }


    async fillFromRedis(readyEvent = true): Promise<void> {

        if (this.isFilled) return;

        await this.redisConfig.getConfig(this.config);

        if (readyEvent) {
            this.isFilled = true;
            this.events.emit('ready');
        }

    }

    protected async removeFromArray(arr: ItemWithId[], id: string) {
        let index = arr.findIndex(x => x.id == id)
        if (index >= 0) {
            arr.splice(index, 1);
        }
    }
    protected async saveToArray(arr: ItemWithId[], item: ItemWithId) {
        let index = arr?.findIndex(x => x.id == item.id)
        if (index >= 0) {
            arr[index] = item;
        }
        else arr.push(item);
    }
    protected async processArray(arr: ItemWithId[], path: RPath, item: ConfigWatch<any>, id?: string) {
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
                const watch = this.executeList[0];
                const item = watch.val;
                let rpath = item.path;
                if (rpath.startsWith('/config')) {
                    let path = rpath.substring(8) as RPath;
                    let val = item.val;
                    let type = item.type;

                    switch (path) {
                        case 'flush':
                            this.config = this.createConfig();
                            break;//sometimes flush
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
                        case 'auth/openId/providers':
                            await this.processArray(this.config.auth.openId.providers, path, item, val.id);
                            break;
                        case 'auth/radius/providers':
                            await this.processArray(this.config.auth.radius.providers, path, item, val.id);
                            break;
                        case 'jwtSSLCertificate':
                            this.config.jwtSSLCertificate = await this.redisConfig.rGet(path) || this.defaultCertificate('JWT', 'jwt');
                            break;
                        case 'webSSLCertificate':
                            this.config.webSSLCertificate = await this.redisConfig.rGet(path) || this.defaultCertificate('Web', 'web');
                            break;
                        case 'caSSLCertificate':
                            this.config.caSSLCertificate = await this.redisConfig.rGet(path) || this.defaultCertificate('ROOT CA', 'ca');
                            break;
                        case 'inSSLCertificates':
                            await this.processArray(this.config.inSSLCertificates, path, item, val.id);
                            break;
                        case 'users':
                            await this.processArray(this.config.users, path, item, val.id);
                            break;
                        case 'groups':
                            await this.processArray(this.config.groups, path, item, val.id);
                            break;
                        case 'services':
                            await this.processArray(this.config.services, path, item, val.id);
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
                            await this.processArray(this.config.networks, path, item, val.id);
                            break;
                        case 'gateways':
                            await this.processArray(this.config.gateways, path, item, val.id);
                            break;
                        case 'authenticationPolicy/rules':
                            await this.processArray(this.config.authenticationPolicy.rules, path, item, val.id);
                            break;
                        case 'authenticationPolicy/rulesOrder':
                            this.config.authenticationPolicy.rulesOrder = await this.redisConfig.rListAll('authenticationPolicy/rulesOrder');
                            break;
                        case 'authorizationPolicy/rules':
                            await this.processArray(this.config.authorizationPolicy.rules, path, item, val.id);
                            break;
                        case 'authorizationPolicy/rulesOrder':
                            this.config.authorizationPolicy.rulesOrder = await this.redisConfig.rListAll('authorizationPolicy/rulesOrder');
                            break;
                        case 'es':
                            this.config.es = await this.redisConfig.rGet(path) || {};
                            break;
                        case 'ipIntelligence/sources':
                            await this.processArray(this.config.ipIntelligence.sources, path, item, val.id);
                            break;
                        case 'ipIntelligence/lists':
                            await this.processArray(this.config.ipIntelligence.lists, path, item, val.id);
                            break;
                        case 'devicePostures':
                            await this.processArray(this.config.devicePostures, path, item, val.id);
                            break;
                        case 'fqdnIntelligence/sources':
                            await this.processArray(this.config.fqdnIntelligence.sources, path, item, val.id);
                            break;
                        case 'fqdnIntelligence/lists':
                            await this.processArray(this.config.fqdnIntelligence.lists, path, item, val.id);
                            break;
                        case 'httpToHttpsRedirect':
                            this.config.httpToHttpsRedirect = await this.redisConfig.rGet('httpToHttpsRedirect') || false
                            break;
                        case 'brand':
                            this.config.brand = await this.redisConfig.rGet(path) || {};
                            break;
                        case 'dns/records':
                            await this.processArray(this.config.dns.records, path, item, val.id);
                            break;
                        default:
                            logger.warn(`not implemented path ${item.path}`);
                            throw new Error(`not implemented path ${item.path}`)
                    }
                    logger.info(`config changed ${watch.val.path} -> ${watch.val.type} id:${watch.val.val?.id || 'unknown'}`)
                    this.executeList.shift();
                    await this.processConfigChanged(watch);
                    this.events.emit('configChanged', watch.val);
                    this.events.emit('log', watch);


                } else {
                    this.executeList.shift();
                    this.events.emit('data', watch);
                    this.events.emit('log', watch);
                }
            }


        } catch (err) {
            logger.error(err);
        }
    }

    async processConfigChanged(watch: WatchItem<ConfigWatch<any>>) {

    }

}



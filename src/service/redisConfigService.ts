import { Util } from "../util";
import { logger } from "../common";
import { ConfigService } from "./configService";
import { RedisService } from "../service/redisService";
import { User } from "../model/user";
import { verify } from "crypto";
import { WatchService } from "./watchService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export class RedisConfigService extends ConfigService {

    isLoadedEveryThing = false;
    timerInterval: any;
    timerInterval2: any;
    lastPos = '$';
    logs: any[] = [];
    isFatalError = false;
    logWatcher: WatchService;
    constructor(private redis: RedisService, private redisStream: RedisService, encryptKey: string, configFile?: string) {
        super(encryptKey, configFile);
        this.logWatcher = new WatchService(redis, redisStream, '/config/logs');

    }


    override loadConfigFromFile(): void {
        this.startLoading();
    }
    saveConfigToFile(): void {

    }

    async startLoading() {
        try {

            this.timerInterval2 = await setIntervalAsync(async () => {
                await this.loadEverything();
            }, 1000)


        } catch (err) {
            logger.error(err);
        }
    }

    async rGetSet(path: string, defaultValue: any, callback?: (val: any) => void) {
        const rpath = `/config/${path}`;
        const type = typeof (defaultValue);
        if (type == 'symbol' || type == 'function')
            throw new Error('not implemented yet');


        try {
            const isExists = await this.redis.containsKey(rpath);
            if (!isExists) {
                await this.redis.set(rpath, defaultValue);
                if (callback)
                    callback(defaultValue);

            } else {
                let val = await this.redis.get(rpath, false) as any;
                if (type == 'number')
                    val = Util.convertToNumber(val);
                if (type == 'boolean')
                    val = Util.convertToBoolean(val as any);
                if (callback)
                    callback(val);
            }

        } finally {

        }
    }


    async rGetObjectArray(path: string, def: any, callback?: (vals: any[]) => void) {
        const rpath = `/config/${path}`;


        try {
            const keys = await this.redis.getAllKeys(`${rpath}/*`);
            if (keys.length) {
                const pipe = await this.redis.multi();
                keys.forEach(x => pipe.get(x));
                const items = await pipe.exec();
                if (callback)
                    callback(items.map((x: string) => JSON.parse(x)));
            } else {
                if (def) {
                    await this.redis.set(`${rpath}/${def.id}`, def);
                    if (callback)
                        callback([def]);
                }
            }


        } finally {

        }
    }


    async loadEverything() {
        try {
            await this.rGetSet('version', this.config.version, (val) => this.config.version = val)
            await this.rGetSet('isConfigured', this.config.isConfigured, (val) => this.config.isConfigured = val);


            await this.rGetObjectArray('users', this.config.users[0], (vals: any[]) => {
                this.config.users = vals;
            })


            await this.rGetObjectArray('groups', null, (vals: any[]) => {
                this.config.groups = vals;
            })

            await this.rGetObjectArray('services', null, (vals: any[]) => {
                this.config.services = vals;
            })

            await this.rGetSet('captcha', this.config.captcha, (val => {
                this.config.captcha = val;
            }))

            await this.rGetSet('jwtSSLCertificate', this.config.jwtSSLCertificate, (val => {
                this.config.jwtSSLCertificate = val;
            }))

            await this.rGetSet('sslCertificate', this.config.sslCertificate, (val => {
                this.config.sslCertificate = val;
            }))

            await this.rGetSet('caSSLCertificate', this.config.caSSLCertificate, (val => {
                this.config.caSSLCertificate = val;
            }))

            await this.rGetSet('domain', this.config.domain, (val => {
                this.config.domain = val;
            }))


            await this.rGetSet('url', this.config.url, (val => {
                this.config.url = val;
            }))

            await this.rGetSet('email', this.config.email, (val => {
                this.config.email = val;
            }))
            await this.rGetSet('logo', this.config.logo, (val => {
                this.config.logo = val;
            }))
            await this.rGetSet('auth/common', this.config.auth.common, (val => {
                this.config.auth.common = val;
            }))
            await this.rGetSet('auth/local', this.config.auth.local, (val => {
                this.config.auth.local = val;
            }))
            await this.rGetObjectArray('auth/ldap/providers', null, (val => {
                this.config.auth.ldap = { providers: [] }
                this.config.auth.ldap.providers = val;
            }))
            await this.rGetObjectArray('auth/oauth/providers', null, (val => {
                this.config.auth.oauth = { providers: [] }
                this.config.auth.oauth.providers = val;
            }))
            await this.rGetObjectArray('auth/saml/providers', null, (val => {
                this.config.auth.saml = { providers: [] }
                this.config.auth.saml.providers = val;
            }))

            await this.rGetObjectArray('networks', this.config.networks[0], (vals: any) => {
                this.config.networks = vals;
            })

            await this.rGetObjectArray('gateways', null, (vals: any) => {
                this.config.gateways = vals;
            })

            await this.rGetObjectArray('authenticationPolicy/rules', null, (vals: any) => {
                this.config.authenticationPolicy.rules = vals;
            })

            await this.rGetObjectArray('authorizationPolicy/rules', null, (vals: any) => {
                this.config.authorizationPolicy.rules = vals;
            })
            this.isLoadedEveryThing = true;
            clearIntervalAsync(this.timerInterval2);
            this.timerInterval2 = null;
        } catch (err) {
            logger.error(err);
        }

    }

    async rGet(path: string, defaultValue: any, callback: (val: any) => Promise<any>) {
        const rpath = `/config/${path}`;
        const type = typeof (defaultValue);
        if (type == 'symbol' || type == 'function')
            throw new Error('not implemented yet');

        try {

            let val = await this.redis.get(rpath, false) as any;
            if (type == 'number')
                val = Util.convertToNumber(val);
            if (type == 'boolean')
                val = Util.convertToBoolean(val as any);
            if (type == 'object')
                val = JSON.parse(type);
            if (callback)
                return callback(val);
            return val;

        } finally {

        }
    }









}
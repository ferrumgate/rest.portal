import fs from "fs";
import { logger } from "../common";
import { Config, ConfigWatch } from "../model/config";
import yaml from 'yaml';
import { Util } from "../util";
import { ApiKey, User } from "../model/user";
import { EmailSetting } from "../model/emailSetting";
import { LogoSetting } from "../model/logoSetting";
import { Captcha } from "../model/captcha";
import { SSLCertificate, SSLCertificateBase, SSLCertificateCategory, SSLCertificateEx } from "../model/cert";
import { ErrorCodes, RestfullException } from "../restfullException";
import { AuthCommon, AuthLdap, AuthLocal, AuthOAuth, AuthOpenId, AuthSaml, AuthSettings, BaseLdap, BaseOAuth, BaseOpenId, BaseRadius, BaseSaml } from "../model/authSettings";
import { RBAC, RBACDefault, Role } from "../model/rbac";
import { HelperService } from "./helperService";
import { Gateway, Network } from "../model/network";
import { Group } from "../model/group";
import { Service } from "../model/service";
import { AuthenticationRule } from "../model/authenticationPolicy";
import { AuthorizationRule } from "../model/authorizationPolicy";
import EventEmitter from "node:events";
import { ESSetting } from "../model/esSetting";
import { stringify } from "querystring";
import { IpIntelligenceCountryList, IpIntelligenceFilterCategory, IpIntelligenceList, IpIntelligenceSource } from "../model/ipIntelligence";
import IPCIDR from "ip-cidr";
import { UtilPKI } from "../utilPKI";
import { DevicePosture } from "../model/authenticationProfile";
import { FqdnIntelligenceList } from "../model/fqdnIntelligence";
import { BrandSetting } from "../model/brandSetting";









/**
 * @summary system config implementation base class
 */
export class ConfigService {

    events: EventEmitter = new EventEmitter();
    config: Config;
    protected configfile = `/etc/ferrumgate/config.yaml`;
    private secretKey = '';


    /**
     *
     */
    constructor(encryptKey: string, configFile?: string) {
        if (!encryptKey)
            throw new Error('needs and encyption key with lenght 32');


        this.secretKey = encryptKey;
        if (configFile)
            this.configfile = configFile;
        this.config = this.createConfig();

        // start point for delete
        //for testing start
        //dont delete aboveline
        try {
            if (process.env.LOAD_TEST_DATA) {
                var m = require('../../test/configServiceTestData');
                m.loadTestData(this.config);
            }
        } catch (err) {
            logger.error(err);
        }


        //dont delete below line
        //for testing end
        // end point for delete
        this.config.lastUpdateTime = new Date().toISOString();
        this.loadConfigFromFile();
        /* if (process.env.LIMITED_MODE == 'true') {
            if (!this.config.groups.find(x => x.id == 'hb16ldst577l9mkf'))
                this.config.groups.push({
                    id: 'hb16ldst577l9mkf',
                    name: 'admin',
                    isEnabled: true, insertDate: new Date().toISOString(), updateDate: new Date().toISOString(), labels: []
                })
            if (!this.config.groups.find(x => x.id == 'pl0m0xh6az722y0t'))
                this.config.groups.push({
                    id: `pl0m0xh6az722y0t`,
                    name: 'remote',
                    isEnabled: true, insertDate: new Date().toISOString(), updateDate: new Date().toISOString(), labels: []
                })
        } */





    }

    createConfig(): Config {
        //default user
        const adminUser = this.createAdminUser();

        //default network
        const defaultNetwork: Network = {
            id: Util.randomNumberString(16),
            name: 'default',
            labels: ['default'],
            clientNetwork: '100.64.0.0/16',
            serviceNetwork: '172.28.28.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isEnabled: true
        }
        return {
            lastUpdateTime: new Date().toISOString(),
            revision: 0,
            version: 1,
            isConfigured: 0,
            users: [
                adminUser
            ],
            groups: [],
            services: [],
            captcha: {},
            jwtSSLCertificate: this.defaultCertificate('JWT', 'jwt'),
            webSSLCertificate: this.defaultCertificate('Web', 'web'),
            caSSLCertificate: this.defaultCertificate('CA', 'ca'),
            inSSLCertificates: [],
            domain: 'ferrumgate.zero',
            url: 'https://secure.yourdomain.com',
            email: this.createDefaultEmail(),
            logo: {},
            auth: {
                common: {},
                local: this.createAuthLocal(),
                ldap: { providers: [] },
                oauth: { providers: [] },
                saml: { providers: [] },
                openId: { providers: [] },
                radius: { providers: [] }

            },
            rbac: {
                roles: [RBACDefault.roleAdmin, RBACDefault.roleReporter, RBACDefault.roleUser],
                rights: [RBACDefault.rightAdmin, RBACDefault.rightReporter, RBACDefault.rightUser]
            },
            networks: [
                defaultNetwork
            ],
            gateways: [],

            authenticationPolicy: {
                rules: [], rulesOrder: []

            },
            authorizationPolicy: { rules: [], rulesOrder: [] },

            es: {},
            flush: 0,
            ipIntelligence: {
                sources: [],
                lists: []
            },
            devicePostures: [],
            fqdnIntelligence: {
                sources: [],
                lists: []
            },
            httpToHttpsRedirect: true,
            brand: {}

        }


    }
    async checkModel() {

    }
    async init() {
        await this.createCerts();
        this.publishEvent('ready');
    }
    async start() {
        await this.init();
    }

    protected defaultCertificate(name: string, category: SSLCertificateCategory) {
        let ssl: SSLCertificate = {
            idEx: Util.randomNumberString(16),
            name: name, insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(), labels: [],
            isEnabled: true, category: category, usages: []
        };
        return ssl;
    }
    protected defaultCertificateEx(name: string, category: SSLCertificateCategory) {
        let ssl: SSLCertificateEx = {
            id: Util.randomNumberString(16),
            name: name, insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(), labels: [],
            isEnabled: true, category: category, usages: []
        };
        return ssl;
    }





    protected async createCerts() {


        //get all certs

        // jwt certificate 
        const jwt = await this.getJWTSSLCertificateSensitive();
        if (!jwt.privateKey) {

            const { publicCrt, privateKey } = await UtilPKI.createCert('FerrumGate JWT CA', 'ferrumgate', 9125, true, []);
            let cert: SSLCertificate = {
                ...jwt,
                publicCrt: publicCrt,
                privateKey: privateKey,
                isSystem: true

            }
            await this.setJWTSSLCertificate(cert);
        }


        //create ca ssl certificate if not exists;
        const ca = await this.getCASSLCertificateSensitive();
        if (!ca.privateKey) {

            const { publicCrt, privateKey } = await UtilPKI.createCert('FerrumGate ROOT CA', 'ferrumgate', 9125, true, []);
            let cert: SSLCertificate = {
                ...ca,
                publicCrt: publicCrt,
                privateKey: privateKey,
                isSystem: true
            }
            await this.setCASSLCertificate(cert);
            ca.privateKey = privateKey, ca.publicCrt = publicCrt;
        }
        //create intermediate web certificates if not exists
        const inCerts = await this.getInSSLCertificateAllSensitive();
        //for tls 
        const intermediateTLS = inCerts.find(x => x.category == 'tls') || this.defaultCertificateEx('TLS ', 'tls');

        if (!intermediateTLS.privateKey) {

            const { publicCrt, privateKey } = await UtilPKI.createCertSigned('FerrumGate Intermediate TLS', 'ferrumgate', 9125, true, [], ca.publicCrt, ca.privateKey);
            let cert: SSLCertificateEx = {
                ...intermediateTLS,
                parentId: ca.idEx,
                publicCrt: publicCrt,
                privateKey: privateKey,
                isSystem: false,
                usages: ['for web', 'for tls inspection', 'for service']

            }
            await this.saveInSSLCertificate(cert);
            intermediateTLS.privateKey = privateKey, intermediateTLS.publicCrt = publicCrt;

        }
        //for authentication inspections

        const intermediateAuthentication = inCerts.find(x => x.category == 'auth') || this.defaultCertificateEx('Authentication', 'auth');

        if (!intermediateAuthentication.privateKey) {

            const { publicCrt, privateKey } = await UtilPKI.createCertSigned('FerrumGate Intermediate Authentication', 'ferrumgate', 9125, true, [], ca.publicCrt, ca.privateKey);
            let cert: SSLCertificateEx = {
                ...intermediateAuthentication,
                parentId: ca.idEx,
                publicCrt: publicCrt,
                privateKey: privateKey,
                isSystem: false

            }
            await this.saveInSSLCertificate(cert);
            intermediateAuthentication.privateKey = privateKey, intermediateAuthentication.publicCrt = publicCrt;

        }


        //create ssl certificates if not exists
        const url = await this.getUrl();
        const domain1 = new URL(url).hostname;

        let webCert = await this.getWebSSLCertificateSensitive();
        if (!webCert?.privateKey) {
            const { publicCrt, privateKey } = await UtilPKI.createCertSigned(domain1, 'ferrumgate', 730, false,
                [
                    { type: 'domain', value: domain1 },

                ], intermediateTLS.publicCrt, intermediateTLS.privateKey);
            let cert: SSLCertificate = {
                ...webCert,
                parentId: intermediateTLS.id,
                publicCrt: publicCrt,
                privateKey: privateKey,

            }
            await this.setWebSSLCertificate(cert);
            webCert.privateKey = privateKey, webCert.publicCrt = publicCrt;
        }
    }
    async stop() {

    }
    publishEvent(ev: string, data?: any) {
        this.events.emit(ev, data);
    }

    isReady() {

    }
    isWritable() {

    }
    isReadable() {

    }

    clone<T>(data: T) {
        return Util.clone(data) as T;
    }



    protected createDefaultEmail(): EmailSetting {
        return {
            type: 'empty',
            fromname: '', pass: '', user: ''
        }
    }

    protected createAuthLocal() {
        let local: AuthLocal = {
            type: 'local',
            baseType: 'local',
            name: 'Local',
            tags: [],
            isForgotPassword: false,
            isRegister: false,
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        return local
    }

    protected createAdminUser() {
        let adminUser = HelperService.createUser('local-local', 'admin', 'default admin', 'ferrumgate');
        adminUser.isVerified = true;
        adminUser.roleIds = ['Admin'];
        return adminUser;
    }
    getEncKey() {
        return this.secretKey;
    }


    async getLastUpdateTime() {
        this.isReady(); this.isReadable();
        return this.config.lastUpdateTime;
    }
    async saveLastUpdateTime() {
        this.isReady(); this.isWritable();
        this.config.lastUpdateTime = new Date().toISOString();
    }
    setConfigPath(path: string) {
        this.configfile = path;
    }
    /**
     * @summary send event about changed entities
     */
    emitEvent<T>(event: ConfigWatch<T>) {
        this.publishEvent('configChanged', event);
        //return event;
    }

    /* private writeAsset(name: string, image: string) {
         const type = image.substring(image.indexOf('/') + 1, image.indexOf(';'));
         const base64Image = image.split(';base64,').pop();
         let path = `./dassets/img`;
         fs.mkdirSync(path, { recursive: true });
         if (type && base64Image) {
             path = `${path}/${name}.${type}`;
             fs.writeFileSync(path, base64Image, { encoding: 'base64url' });
         }
         return path;
     }
     saveAssets() {
         if (this.config.logo.default) {
             this.config.logo.defaultPath = this.writeAsset('logo', this.config.logo.default);
 
         }
     } */

    loadConfigFromFile() {
        logger.info(`loading configuration from ${this.configfile}`);
        if (fs.existsSync(this.configfile)) {
            const content = fs.readFileSync(this.configfile, 'utf-8').toString();
            if (process.env.NODE_ENV == 'development') {
                this.config = yaml.parse(content);
            } else {
                const decrpted = Util.decrypt(this.secretKey, content, 'base64url');
                this.config = yaml.parse(decrpted);
            }
        }
        //this.saveAssets();
    }
    async saveConfigToFile() {
        const str = yaml.stringify(this.config);
        if (process.env.NODE_ENV == 'development') {

            fs.writeFileSync(this.configfile, str, { encoding: 'utf-8' });
        } else {
            const encrypted = Util.encrypt(this.secretKey, str, 'base64url');
            fs.writeFileSync(this.configfile, encrypted, { encoding: 'utf-8' });
        }
        await this.saveLastUpdateTime();


    }
    async saveConfigToString() {
        const str = yaml.stringify(this.config);
        if (process.env.NODE_ENV == 'development') {
            return str;
        } else {
            const encrypted = Util.encrypt(this.secretKey, str, 'base64url');
            return encrypted;
        }
    }

    protected deleteUserSensitiveData(user?: User) {
        delete user?.apiKey?.key;
        delete user?.twoFASecret;
        delete user?.password;
        delete user?.cert?.privateKey;
        delete user?.cert?.publicCrt;

    }


    async getUserByUsername(username: string): Promise<User | undefined> {
        this.isReady(); this.isReadable();
        if (!username) return undefined;
        let user = this.clone(this.config.users.find(x => x.username == username));
        this.deleteUserSensitiveData(user);
        return user;
    }
    async getUserByUsernameAndSource(username: string, source: string): Promise<User | undefined> {
        this.isReady(); this.isReadable();
        if (!username) return undefined;
        let user = this.clone(this.config.users.find(x => x.username == username && x.source == source));
        this.deleteUserSensitiveData(user);
        return user;
    }
    /*   async getUserByApiKey(key: string): Promise<User | undefined> {
          this.isReady(); this.isReadable();
          if (!key) return undefined;
          let user = this.clone(this.config.users.find(x => x.apiKey?.key == key));
          this.deleteUserSensitiveData(user);
          return user;
      } */
    async getUserById(id: string): Promise<User | undefined> {
        this.isReady(); this.isReadable();
        let user = this.clone(this.config.users.find(x => x.id == id));
        this.deleteUserSensitiveData(user);
        return user;
    }



    async getUsersBy(page: number = 0, pageSize: number = 0, search?: string,
        ids?: string[], groupIds?: string[], roleIds?: string[], loginMethods?: string[],
        is2FA?: boolean, isVerified?: boolean, isLocked?: boolean,
        isEmailVerified?: boolean) {
        this.isReady(); this.isReadable();
        let users = [];
        let filteredUsers = !search ? this.config.users :
            this.config.users.filter(x => {
                let caseInsensitivie = search.toLowerCase();
                if (x.name.toLowerCase().includes(caseInsensitivie))
                    return true;
                if (x.username.toLowerCase().includes(caseInsensitivie))
                    return true;
                if (x.email?.toLowerCase().includes(caseInsensitivie))
                    return true;
                if (x.source.toLocaleLowerCase().includes(caseInsensitivie))
                    return true;
                if (x.labels?.find(x => x.toLowerCase().includes(caseInsensitivie)))
                    return true;
                return false;

            })
        if (ids && ids.length)
            filteredUsers = filteredUsers.filter(x => ids.includes(x.id));
        if (groupIds && groupIds.length)
            filteredUsers = filteredUsers.filter(x => Util.isArrayElementExist(x.groupIds, groupIds));
        if (roleIds && roleIds.length)
            filteredUsers = filteredUsers.filter(x => Util.isArrayElementExist(x.roleIds, roleIds));
        if (loginMethods && loginMethods.length) {
            filteredUsers = filteredUsers.filter(x => (loginMethods.includes('password') && x.password) || (loginMethods.includes('apiKey') && x.apiKey) || (loginMethods.includes('certificate') && x.cert))
        }

        if (!Util.isUndefinedOrNull(is2FA))
            filteredUsers = filteredUsers.filter(x => Boolean(x.is2FA) == is2FA)
        if (!Util.isUndefinedOrNull(isVerified))
            filteredUsers = filteredUsers.filter(x => Boolean(x.isVerified) == isVerified)
        if (!Util.isUndefinedOrNull(isLocked))
            filteredUsers = filteredUsers.filter(x => Boolean(x.isLocked) == isLocked)

        if (!Util.isUndefinedOrNull(isEmailVerified))
            filteredUsers = filteredUsers.filter(x => Boolean(x.isEmailVerified) == isEmailVerified)



        filteredUsers = Array.from(filteredUsers);
        filteredUsers.sort((a, b) => {
            return a.username.localeCompare(b.username)
        })
        const totalSize = filteredUsers.length;
        if (pageSize)
            filteredUsers = filteredUsers.slice(page * pageSize, (page + 1) * pageSize);
        for (const iterator of filteredUsers) {
            let user = this.clone(iterator);
            this.deleteUserSensitiveData(user);
            users.push(user);
        }

        return { items: users, total: totalSize };
    }
    async getUserByRoleIds(roleIds: string[]): Promise<User[]> {
        this.isReady(); this.isReadable();
        let users = [];
        const filteredUsers = this.config.users.filter(x => Util.isArrayElementExist(roleIds, x.roleIds))
        for (const iterator of filteredUsers) {
            let user = this.clone(iterator);
            this.deleteUserSensitiveData(user);
            users.push(user);
        }

        return users;
    }
    async getUserCount() {
        this.isReady(); this.isReadable();
        return this.config.users.length;
    }


    async getUserRoles(user: User) {
        const rbac = await this.getRBAC();
        //const sensitiveData = await this.getUserSensitiveData(user.id);
        return RBACDefault.convert2RoleList(rbac, user.roleIds);
    }
    async getUserByUsernameAndPass(username: string, pass: string): Promise<User | undefined> {
        this.isReady(); this.isReadable();
        if (!username) return undefined;
        if (!username.trim()) return undefined;
        let user = this.config.users
            .find(x => x.username == username);

        if (user && Util.bcryptCompare(pass, user.password || '')) {
            let cloned = this.clone(user);
            this.deleteUserSensitiveData(cloned);
            return cloned;
        }
        return undefined;

    }
    async getUserByIdAndPass(id: string, pass: string): Promise<User | undefined> {
        this.isReady(); this.isReadable();
        if (!id) return undefined;
        if (!id.trim()) return undefined;
        let user = this.config.users
            .find(x => x.id == id);

        if (user && Util.bcryptCompare(pass, user.password || '')) {
            let cloned = this.clone(user);
            this.deleteUserSensitiveData(cloned);
            return cloned;
        }
        return undefined;

    }
    async getUserSensitiveData(id: string): Promise<{ twoFASecret?: string, apiKey?: ApiKey, cert?: SSLCertificateBase }> {
        this.isReady(); this.isReadable();
        let user = this.clone(this.config.users.find(x => x.id == id)) as User;
        let item = {
            twoFASecret: user?.twoFASecret,
            apiKey: user.apiKey ? {
                ...user.apiKey
            } : undefined,
            cert: user.cert ? {
                ...user.cert
            } : undefined
        }
        delete item.cert?.privateKey;
        return item;
    }


    protected async triggerUserDeleted(user: User) {
        //check policy authentication

        let rulesAuthnChanged: { previous: AuthenticationRule, item: AuthenticationRule }[] = [];
        let rulesAuthnDeleted: { previous: AuthenticationRule }[] = [];
        this.config.authenticationPolicy.rules.forEach((x, index, arr) => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == user.id);
            if (userIdIndex >= 0) {
                const prev = this.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);
                if (x.userOrgroupIds.length)
                    rulesAuthnChanged.push({ previous: prev, item: x });
                else {
                    arr.splice(index, 1);
                    rulesAuthnDeleted.push({ previous: prev })
                }
            }
        })
        //check authorization

        let rulesAuthzChanged: { previous: AuthorizationRule, item: AuthorizationRule }[] = [];
        let rulesAuthzDeleted: { previous: AuthorizationRule }[] = [];
        this.config.authorizationPolicy.rules.forEach((x, index, arr) => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == user.id);
            if (userIdIndex >= 0) {
                const prev = this.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);
                if (x.userOrgroupIds.length)
                    rulesAuthzChanged.push({ previous: prev, item: x });
                else {
                    arr.splice(index, 1);
                    rulesAuthzDeleted.push({ previous: prev })
                }
            }
        })

        rulesAuthnChanged.forEach(x => {
            const trc = this.createTrackEvent(x.previous, x.item)
            this.emitEvent({ type: 'put', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before })
        })
        rulesAuthnDeleted.forEach(x => {
            const trc = this.createTrackEvent(x.previous)
            this.emitEvent({ type: 'del', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before })
        })

        rulesAuthzChanged.forEach(x => {
            const trc = this.createTrackEvent(x.previous, x.item)
            this.emitEvent({ type: 'put', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before });
        })
        rulesAuthzDeleted.forEach(x => {
            const trc = this.createTrackEvent(x.previous)
            this.emitEvent({ type: 'del', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before });
        })

        const trc = this.createTrackEvent(user)
        this.emitEvent({ type: 'del', path: 'users', val: trc.after, before: trc.before });


    }
    async deleteUser(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.users.findIndex(x => x.id == id);
        const user = this.config.users[indexId];
        if (indexId >= 0 && user) {
            this.config.users.splice(indexId, 1);
            await this.saveConfigToFile();
            await this.triggerUserDeleted(user);
        }

        return this.createTrackEvent(user);
    }


    async saveUser(user: User) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(user);

        let findedIndex = this.config.users.findIndex(x => x.username == user.username);
        let finded = this.config.users[findedIndex];
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.users.push(cloned);
            findedIndex = this.config.users.length - 1;
            const trc = this.createTrackEvent(finded, this.config.users[findedIndex])
            this.emitEvent({ type: 'put', path: 'users', val: trc.after, before: trc.before })

        }
        else {
            cloned.id = finded.id;//security
            const apiKey = (finded.apiKey || cloned.apiKey) ? {
                ...finded.apiKey,
                ...cloned.apiKey
            } : undefined;
            const cert: SSLCertificateBase | undefined = (finded.cert || cloned.cert) ? {
                ...finded.cert,
                ...cloned.cert
            } : undefined

            this.config.users[findedIndex] = {
                ...finded,
                ...cloned,
                apiKey: apiKey,
                cert: cert,
                updateDate: new Date().toISOString(),

            }
            const trc = this.createTrackEvent(finded, this.config.users[findedIndex])
            this.emitEvent({ type: 'put', path: 'users', val: trc.after, before: trc.before })

        }

        await this.saveConfigToFile();
        return this.createTrackEvent(finded, this.config.users[findedIndex]);

    }
    async changeAdminUser(email: string, password: string) {
        this.isReady(); this.isWritable();
        let finded = this.config.users.find(x => x.username == 'admin');
        if (!finded)
            return;
        const prev = this.clone(finded);
        finded.username = email;
        finded.name = email;
        finded.password = Util.bcryptHash(password);
        finded.updateDate = new Date().toISOString();
        const trc = this.createTrackEvent(prev, finded)
        this.emitEvent({ type: 'put', path: 'users', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, finded);
    }
    async getCaptcha(): Promise<Captcha> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.captcha);
    }

    async setCaptcha(captcha: Captcha | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(captcha);
        const prev = this.config.captcha;
        this.config.captcha = {
            ...this.config.captcha,
            ...cloned
        }
        const trc = this.createTrackEvent(prev, this.config.captcha)
        this.emitEvent({ type: 'put', path: 'captcha', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.captcha);
    }

    async getJWTSSLCertificateSensitive(): Promise<SSLCertificate> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.jwtSSLCertificate);
    }
    async getJWTSSLCertificate(): Promise<SSLCertificate> {
        return this.deleteCertSensitive(await this.getJWTSSLCertificateSensitive()) as SSLCertificate;
    }

    async setJWTSSLCertificate(cert: SSLCertificate | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(cert);
        const prev = this.config.jwtSSLCertificate;
        this.config.jwtSSLCertificate = {
            ...this.config.jwtSSLCertificate,
            ...cloned
        }
        const trc = this.createTrackEvent(prev, this.config.jwtSSLCertificate)
        this.emitEvent({ type: 'put', path: 'jwtSSLCertificate', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.jwtSSLCertificate);
    }

    async getWebSSLCertificateSensitive(): Promise<SSLCertificate> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.webSSLCertificate);
    }
    async getWebSSLCertificate(): Promise<SSLCertificate> {
        return this.deleteCertSensitive(await this.getWebSSLCertificateSensitive()) as SSLCertificate;
    }


    async setWebSSLCertificate(cert: SSLCertificate | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(cert);
        const prev = this.config.webSSLCertificate;
        this.config.webSSLCertificate = {
            ...this.config.webSSLCertificate,
            ...cloned
        }
        const trc = this.createTrackEvent(prev, this.config.webSSLCertificate);
        this.emitEvent({ type: 'put', path: 'webSSLCertificate', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.webSSLCertificate);
    }
    protected deleteCertSensitive(cert?: SSLCertificate | SSLCertificateEx) {
        if (!cert) return cert;
        delete cert.privateKey;
        if (cert.letsEncrypt)
            delete cert.letsEncrypt.privateKey;
        return cert;
    }


    async getCASSLCertificateSensitive(): Promise<SSLCertificate> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.caSSLCertificate);
    }
    async getCASSLCertificate(): Promise<SSLCertificate> {
        return this.deleteCertSensitive(await this.getCASSLCertificateSensitive()) as SSLCertificate;
    }

    async setCASSLCertificate(cert: SSLCertificate | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(cert);
        const prev = this.config.caSSLCertificate;
        this.config.caSSLCertificate = {
            ...this.config.caSSLCertificate,
            ...cloned
        }
        const trc = this.createTrackEvent(prev, this.config.caSSLCertificate)
        this.emitEvent({ type: 'put', path: 'caSSLCertificate', val: trc.after, before: trc.after })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.caSSLCertificate);
    }

    //// intermediate certificates 
    async getInSSLCertificateSensitive(id: string): Promise<SSLCertificateEx | undefined> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.inSSLCertificates.find(x => x.id == id));

    }
    async getInSSLCertificate(id: string): Promise<SSLCertificateEx | undefined> {
        return this.deleteCertSensitive(await this.getInSSLCertificateSensitive(id)) as SSLCertificateEx;

    }

    async getInSSLCertificateAll(): Promise<SSLCertificateEx[]> {

        return (await this.getInSSLCertificateAllSensitive()).map(x => this.deleteCertSensitive(x)).filter(y => y).map(y => y as SSLCertificateEx);


    }
    async getInSSLCertificateAllSensitive() {
        this.isReady(); this.isReadable();
        return this.config.inSSLCertificates.map(x => this.clone(x));
    }



    async deleteInSSLCertificate(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.inSSLCertificates.findIndex(x => x.id == id);
        const cert = this.config.inSSLCertificates.find(x => x.id == id);
        if (indexId >= 0 && cert) {
            this.config.inSSLCertificates.splice(indexId, 1);
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(cert);


    }
    /**
     * @summary save intermediate certificate
     */
    async saveInSSLCertificate(cert: SSLCertificateEx) {
        this.isReady(); this.isWritable();
        let findedIndex = this.config.inSSLCertificates.findIndex(x => x.id == cert.id);
        let finded = findedIndex >= 0 ? this.config.inSSLCertificates[findedIndex] : null;
        const cloned = this.clone(cert);
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            this.config.inSSLCertificates.push(cloned);
            findedIndex = this.config.inSSLCertificates.length - 1;

            const trc = this.createTrackEvent(finded, this.config.inSSLCertificates[findedIndex]);
            this.emitEvent({ type: 'put', path: 'inSSLCertificates', val: trc.after, before: trc.before })
        } else {
            this.config.inSSLCertificates[findedIndex] = {
                ...finded,
                ...cloned,
            }
            const trc = this.createTrackEvent(finded, this.config.inSSLCertificates[findedIndex]);
            this.emitEvent({ type: 'put', path: 'inSSLCertificates', val: trc.after, before: trc.before })
        }
        await this.saveConfigToFile();
        return this.createTrackEvent(finded, this.config.inSSLCertificates[findedIndex]);
    }





    async getEmailSetting(): Promise<EmailSetting> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.email);
    }

    async setEmailSetting(options: EmailSetting) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(options);
        let prev = this.config.email;
        this.config.email = {
            ...this.config.email,
            ...cloned
        }
        const trc = this.createTrackEvent(prev, this.config.email)
        this.emitEvent({ type: 'put', path: 'email', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.email);
    }

    async getLogo(): Promise<LogoSetting> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.logo);
    }
    async setLogo(logo: LogoSetting | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(logo);
        let prev = this.config.logo;
        this.config.logo = {
            ...this.config.logo,
            ...cloned
        }
        const trc = this.createTrackEvent(prev, this.config.logo);
        this.emitEvent({ type: 'put', path: 'logo', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.logo);
    }


    async setAuthSettingCommon(common: AuthCommon) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(common);
        let prev = this.config.auth.common;
        this.config.auth.common = cloned;
        const trc = this.createTrackEvent(prev, this.config.auth.common)
        this.emitEvent({ type: 'put', path: 'auth/common', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.auth.common);
    }

    async getAuthSettingCommon() {
        this.isReady(); this.isReadable();
        const common = this.clone(this.config.auth.common);
        return common;
    }


    async setAuthSettingLocal(local: AuthLocal) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(local);
        const prev = this.config.auth.local;
        this.config.auth.local = cloned;
        const trc = this.createTrackEvent(prev, this.config.auth.local);
        this.emitEvent({ type: 'put', path: 'auth/local', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.auth.local);
    }
    async getAuthSettingLocal() {
        this.isReady(); this.isReadable();
        const common = this.clone(this.config.auth.local);
        return common;
    }

    async getAuthSettingOAuth() {
        this.isReady(); this.isReadable();
        return this.clone(this.config.auth.oauth || {}) as AuthOAuth
    }

    async addAuthSettingOAuth(provider: BaseOAuth) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(provider);
        if (!this.config.auth.oauth)
            this.config.auth.oauth = { providers: [] };
        let index = this.config.auth.oauth.providers.findIndex(x => x.id == cloned.id);
        const previous = this.config.auth.oauth.providers[index];

        if (index < 0) {
            this.config.auth.oauth.providers.push(cloned);
            index = this.config.auth.oauth.providers.length - 1;
            const trc = this.createTrackEvent(previous, this.config.auth.oauth.providers[index])
            this.emitEvent({ type: 'put', path: 'auth/oauth/providers', val: trc.after, before: trc.before })
        }
        else {
            this.config.auth.oauth.providers[index] = {
                ...cloned
            }
            const trc = this.createTrackEvent(previous, this.config.auth.oauth.providers[index])
            this.emitEvent({ type: 'put', path: 'auth/oauth/providers', val: trc.after, before: trc.before })
        }

        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.auth.oauth.providers[index]);
    }

    async deleteAuthSettingOAuth(id: string) {
        this.isReady(); this.isWritable();
        const index = this.config.auth?.oauth?.providers.findIndex(x => x.id == id);
        const provider = this.config.auth?.oauth?.providers.find(x => x.id == id);
        if (Number(index) >= 0 && provider) {

            this.config.auth.oauth?.providers.splice(Number(index), 1);
            const trc = this.createTrackEvent(provider);
            this.emitEvent({ type: 'del', path: 'auth/oauth/providers', val: trc.after, before: trc.before })
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(provider);
    }

    async getAuthSettingLdap() {
        this.isReady(); this.isReadable();
        return this.clone(this.config.auth.ldap || {}) as AuthLdap
    }
    async addAuthSettingLdap(provider: BaseLdap) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(provider);
        if (!this.config.auth.ldap)
            this.config.auth.ldap = { providers: [] };
        let index = this.config.auth.ldap.providers.findIndex(x => x.id == cloned.id);
        const previous = this.config.auth.ldap.providers[index];

        if (index < 0) {
            this.config.auth.ldap.providers.push(cloned);
            index = this.config.auth.ldap.providers.length - 1;
            const trc = this.createTrackEvent(this.config.auth.ldap.providers[index]);
            this.emitEvent({ type: 'put', path: 'auth/ldap/providers', val: trc.after, before: trc.before })
        }
        else {
            this.config.auth.ldap.providers[index] = {
                ...cloned
            }
            const trc = this.createTrackEvent(this.config.auth.ldap.providers[index])
            this.emitEvent({ type: 'put', path: 'auth/ldap/providers', val: trc.after, before: trc.before })
        }
        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.auth.ldap.providers[index]);
    }
    async deleteAuthSettingLdap(id: string) {
        this.isReady(); this.isWritable();
        const index = this.config.auth?.ldap?.providers.findIndex(x => x.id == id);
        const provider = this.config.auth?.ldap?.providers.find(x => x.id == id);
        if (Number(index) >= 0 && provider) {
            this.config.auth.ldap?.providers.splice(Number(index), 1);
            const trc = this.createTrackEvent(provider)
            this.emitEvent({ type: 'del', path: 'auth/ldap/providers', val: trc.after, before: trc.before })
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(provider);
    }

    async getAuthSettingSaml() {
        this.isReady(); this.isReadable();
        return this.clone(this.config.auth.saml || {}) as AuthSaml
    }


    async addAuthSettingSaml(provider: BaseSaml) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(provider);
        if (!this.config.auth.saml)
            this.config.auth.saml = { providers: [] };
        let index = this.config.auth.saml.providers.findIndex(x => x.id == cloned.id);
        const previous = this.config.auth.saml.providers[index];
        if (index < 0) {
            this.config.auth.saml.providers.push(cloned);
            index = this.config.auth.saml.providers.length - 1;
            const trc = this.createTrackEvent(this.config.auth.saml.providers[index])
            this.emitEvent({ type: 'put', path: 'auth/saml/providers', val: trc.after, before: trc.before })
        }
        else {
            this.config.auth.saml.providers[index] = {
                ...cloned
            }
            const trc = this.createTrackEvent(previous, this.config.auth.saml.providers[index])
            this.emitEvent({ type: 'put', path: 'auth/saml/providers', val: trc.after, before: trc.before })
        }

        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.auth.saml.providers[index]);
    }


    async deleteAuthSettingSaml(id: string) {
        this.isReady(); this.isWritable();
        const index = this.config.auth?.saml?.providers.findIndex(x => x.id == id);
        const provider = this.config.auth?.saml?.providers.find(x => x.id == id);
        if (Number(index) >= 0 && provider) {
            this.config.auth.saml?.providers.splice(Number(index), 1);
            const trc = this.createTrackEvent(provider);
            this.emitEvent({ type: 'del', path: 'auth/saml/providers', val: trc.after, before: trc.before })
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(provider);
    }


    async getAuthSettingOpenId() {
        this.isReady(); this.isReadable();
        return this.clone(this.config.auth.openId || {}) as AuthOpenId
    }


    async addAuthSettingOpenId(provider: BaseOpenId) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(provider);
        if (!this.config.auth.openId)
            this.config.auth.openId = { providers: [] };
        let index = this.config.auth.openId.providers.findIndex(x => x.id == cloned.id);
        const previous = this.config.auth.openId.providers[index];
        if (index < 0) {
            this.config.auth.openId.providers.push(cloned);
            index = this.config.auth.openId.providers.length - 1;
            const trc = this.createTrackEvent(this.config.auth.openId.providers[index])
            this.emitEvent({ type: 'put', path: 'auth/openId/providers', val: trc.after, before: trc.before })
        }
        else {
            this.config.auth.openId.providers[index] = {
                ...cloned
            }
            const trc = this.createTrackEvent(previous, this.config.auth.openId.providers[index])
            this.emitEvent({ type: 'put', path: 'auth/openId/providers', val: trc.after, before: trc.before })
        }

        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.auth.openId.providers[index]);
    }


    async deleteAuthSettingOpenId(id: string) {
        this.isReady(); this.isWritable();
        const index = this.config.auth?.openId?.providers.findIndex(x => x.id == id);
        const provider = this.config.auth?.openId?.providers.find(x => x.id == id);
        if (Number(index) >= 0 && provider) {
            this.config.auth.openId?.providers.splice(Number(index), 1);
            const trc = this.createTrackEvent(provider);
            this.emitEvent({ type: 'del', path: 'auth/openId/providers', val: trc.after, before: trc.before })
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(provider);
    }


    async getAuthSettingRadius() {
        this.isReady(); this.isReadable();
        return this.clone(this.config.auth.radius || {}) as AuthOpenId
    }


    async addAuthSettingRadius(provider: BaseRadius) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(provider);
        if (!this.config.auth.radius)
            this.config.auth.radius = { providers: [] };
        let index = this.config.auth.radius.providers.findIndex(x => x.id == cloned.id);
        const previous = this.config.auth.radius.providers[index];
        if (index < 0) {
            this.config.auth.radius.providers.push(cloned);
            index = this.config.auth.radius.providers.length - 1;
            const trc = this.createTrackEvent(this.config.auth.radius.providers[index])
            this.emitEvent({ type: 'put', path: 'auth/radius/providers', val: trc.after, before: trc.before })
        }
        else {
            this.config.auth.radius.providers[index] = {
                ...cloned
            }
            const trc = this.createTrackEvent(previous, this.config.auth.radius.providers[index])
            this.emitEvent({ type: 'put', path: 'auth/radius/providers', val: trc.after, before: trc.before })
        }

        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.auth.radius.providers[index]);
    }


    async deleteAuthSettingRadius(id: string) {
        this.isReady(); this.isWritable();
        const index = this.config.auth?.radius?.providers.findIndex(x => x.id == id);
        const provider = this.config.auth?.radius?.providers.find(x => x.id == id);
        if (Number(index) >= 0 && provider) {
            this.config.auth.radius?.providers.splice(Number(index), 1);
            const trc = this.createTrackEvent(provider);
            this.emitEvent({ type: 'del', path: 'auth/radius/providers', val: trc.after, before: trc.before })
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(provider);
    }

    async getNetwork(id: string) {
        this.isReady(); this.isReadable();
        const network = this.config.networks.find(x => x.id == id);
        if (!network) {
            return network;
        }
        return this.clone(network);
    }
    async getNetworkCount() {
        this.isReady(); this.isReadable();
        return this.config.networks.length;
    }

    protected async triggerNetworkDeleted(net: Network) {
        ////// gateways
        let changedGateways = this.config.gateways.filter(x => x.networkId == net.id);
        changedGateways.forEach(x => {
            let previous = this.clone(x);
            x.networkId = '';
            const trc = this.createTrackEvent(previous, x)
            this.emitEvent({ type: "put", path: 'gateways', val: trc.after, before: trc.before })
        });

        //////////services

        let deleteServices = this.config.services.filter(x => x.networkId == net.id);
        this.config.services = this.config.services.filter(x => x.networkId != net.id);
        deleteServices.forEach(x => {
            const trc = this.createTrackEvent(x)
            this.emitEvent({ type: 'del', path: 'services', val: trc.after, before: trc.before });
        })

        //// policy authorization
        let deleteAuthorizationRules = this.config.authorizationPolicy.rules.filter(x => x.networkId == net.id);
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => x.networkId != net.id);
        deleteAuthorizationRules.forEach(x => {
            const trc = this.createTrackEvent(x);
            this.emitEvent({ type: 'del', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before });
        })
        //check one more
        let deleteServicesId = deleteServices.map(x => x.id);
        let deleteAuthorizatonRules2 = this.config.authorizationPolicy.rules.filter(x => deleteServicesId.includes(x.serviceId));
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => !deleteServicesId.includes(x.serviceId));
        deleteAuthorizatonRules2.forEach(x => {
            const trc = this.createTrackEvent(x);
            this.emitEvent({ type: 'del', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before });
        })


        //policy authentication
        let deleteAuthenticationRules = this.config.authenticationPolicy.rules.filter(x => x.networkId == net.id);
        this.config.authenticationPolicy.rules = this.config.authenticationPolicy.rules.filter(x => x.networkId != net.id);
        deleteAuthenticationRules.forEach(x => {
            const trc = this.createTrackEvent(x);
            this.emitEvent({ type: 'del', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before });
        })

        const trc = this.createTrackEvent(net);
        this.emitEvent({ type: 'del', path: 'networks', val: trc.after, before: trc.before });

    }

    async deleteNetwork(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.networks.findIndex(x => x.id == id);
        const network = this.config.networks.find(x => x.id == id);
        if (indexId >= 0 && network) {
            this.config.networks.splice(indexId, 1);
            await this.triggerNetworkDeleted(network)
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(network)

    }

    async getNetworkByName(name: string) {
        this.isReady(); this.isReadable();
        const network = this.config.networks.find(x => x.name == name);
        if (!network) {
            return network;
        }
        return this.clone(network);
    }
    async getNetworkByGateway(gatewayId: string) {
        this.isReady(); this.isReadable();
        const gateway = this.config.gateways.find(x => x.id == gatewayId);
        if (!gateway || !gateway.networkId) {
            return null;
        }
        const network = this.config.networks.find(x => x.id == gateway.networkId);
        if (!network) return null;
        return this.clone(network);
    }

    async getNetworksBy(query: string) {
        this.isReady(); this.isReadable();
        const networks = this.config.networks.filter(x => {
            if (x.labels?.length && x.labels.find(y => y.toLowerCase().includes(query)))
                return true;
            if (x.name?.toLowerCase().includes(query))
                return true;
            if (x.serviceNetwork.includes(query))
                return true;
            if (x.clientNetwork.includes(query))
                return true;
            return false;
        });
        return networks.map(x => this.clone(x));
    }
    async getNetworksAll() {
        this.isReady(); this.isReadable();
        return this.config.networks.map(x => this.clone(x));
    }


    async saveNetwork(network: Network) {
        this.isReady(); this.isReadable();
        let findedIndex = this.config.networks.findIndex(x => x.id == network.id);
        let finded = this.config.networks[findedIndex];
        const cloned = this.clone(network);
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.networks.push(cloned);
            findedIndex = this.config.networks.length - 1;
            const trc = this.createTrackEvent(finded, this.config.networks[findedIndex]);
            this.emitEvent({ type: 'put', path: 'networks', val: trc.after, before: trc.before });
        } else {
            this.config.networks[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            const trc = this.createTrackEvent(finded, this.config.networks[findedIndex])
            this.emitEvent({ type: 'put', path: 'networks', val: trc.after, before: trc.before });
        }
        await this.saveConfigToFile();
        return this.createTrackEvent(finded, this.config.networks[findedIndex]);
    }
    async getDomain(): Promise<string> {
        this.isReady(); this.isReadable();
        return this.config.domain;
    }

    async setDomain(domain: string) {
        this.isReady(); this.isWritable();
        let previous = this.config.domain;
        this.config.domain = domain;
        const trc = this.createTrackEvent(previous, this.config.domain)
        this.emitEvent({ type: 'put', path: 'domain', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.domain);
    }

    async getGateway(id: string) {
        this.isReady(); this.isReadable();
        const gateway = this.config.gateways.find(x => x.id == id);
        if (!gateway) {
            return gateway;
        }
        return this.clone(gateway);
    }
    async getGatewayCount() {
        this.isReady(); this.isReadable();
        return this.config.gateways.length;
    }
    protected async triggerGatewayDeleted(gate: Gateway) {
        const trc = this.createTrackEvent(gate);
        this.emitEvent({ type: 'del', path: 'gateways', val: trc.after, before: trc.before });
    }

    async deleteGateway(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.gateways.findIndex(x => x.id == id);
        const gateway = this.config.gateways.find(x => x.id == id);
        if (indexId >= 0 && gateway) {
            this.config.gateways.splice(indexId, 1);
            await this.triggerGatewayDeleted(gateway);
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(gateway);

    }
    async getGatewaysByNetworkId(id: string) {
        this.isReady(); this.isReadable();
        if (id) {
            const gateways = this.config.gateways.filter(x => x.networkId == id);
            return gateways.map(x => this.clone(x));
        } else {
            const gateways = this.config.gateways.filter(x => !x.networkId);
            return gateways.map(x => this.clone(x));
        }
    }
    async getGatewaysBy(query: string) {
        this.isReady(); this.isReadable();
        const gateways = this.config.gateways.filter(x => {
            if (x.labels?.length && x.labels.find(y => y.toLowerCase().includes(query)))
                return true;
            if (x.name?.toLowerCase().includes(query))
                return true;
            return false;
        });
        return gateways;
    }

    async getGatewaysAll() {
        this.isReady(); this.isReadable();
        return this.config.gateways.map(x => this.clone(x));
    }

    async saveGateway(gateway: Gateway) {
        this.isReady(); this.isWritable();
        let findedIndex = this.config.gateways.findIndex(x => x.id == gateway.id);
        let finded = findedIndex >= 0 ? this.config.gateways[findedIndex] : null;
        const cloned = this.clone(gateway);
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.gateways.push(cloned);
            findedIndex = this.config.gateways.length - 1;
            const trc = this.createTrackEvent(finded, this.config.gateways[findedIndex]);
            this.emitEvent({ type: 'put', path: 'gateways', val: trc.after, before: trc.before });
        } else {
            this.config.gateways[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            const trc = this.createTrackEvent(finded, this.config.gateways[findedIndex]);
            this.emitEvent({ type: 'put', path: 'gateways', val: trc.after, before: trc.before });
        }
        await this.saveConfigToFile();
        return await this.createTrackEvent(finded, this.config.gateways[findedIndex]);
    }




    async getUrl(): Promise<string> {
        this.isReady(); this.isReadable();
        return this.config.url;
    }
    async setUrl(url: string) {
        this.isReady(); this.isWritable();
        let previous = this.config.url;
        this.config.url = url;
        const trc = this.createTrackEvent(previous, this.config.url)
        this.emitEvent({ type: 'put', path: 'url', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.url);
    }

    async getRBAC(): Promise<RBAC> {

        return this.clone(this.config.rbac);
    }

    async getIsConfigured(): Promise<number> {
        this.isReady(); this.isReadable();
        return this.config.isConfigured;
    }

    async setIsConfigured(val: number) {
        this.isReady(); this.isWritable();
        let previous = this.config.isConfigured;
        this.config.isConfigured = val;
        const trc = this.createTrackEvent(previous, this.config.isConfigured)
        this.emitEvent({ type: 'put', path: 'isConfigured', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.isConfigured);
    }

    //// group entity
    async getGroup(id: string): Promise<Group | undefined> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.groups.find(x => x.id == id));

    }
    async getGroupCount() {
        this.isReady(); this.isReadable();
        return this.config.groups.length;
    }

    async getGroupsBySearch(query: string) {
        this.isReady(); this.isReadable();
        const search = query.toLowerCase();
        const groups = this.config.groups.filter(x => {
            if (x.labels?.length && x.labels.find(y => y.toLowerCase().includes(search)))
                return true;
            if (x.name?.toLowerCase().includes(search))
                return true;

            return false;
        });
        return groups.map(x => this.clone(x));
    }
    async getGroupsAll() {
        this.isReady(); this.isReadable();
        return this.config.groups.map(x => this.clone(x));
    }

    protected async triggerDeleteGroup(grp: Group) {

        let usersChanged: { previous: User, item: User }[] = [];
        this.config.users.forEach(x => {
            let userGroupIndex = x.groupIds.findIndex(y => y == grp.id)
            if (userGroupIndex >= 0) {
                let cloned = this.clone(x);
                x.groupIds.splice(userGroupIndex, 1);
                usersChanged.push({ previous: cloned, item: x })
            }
        })

        //check policy authentication

        let rulesAuthnChanged: { previous: AuthenticationRule, item: AuthenticationRule }[] = [];
        let rulesAuthnDeleted: { previous: AuthenticationRule }[] = [];
        this.config.authenticationPolicy.rules.forEach((x, index, arr) => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == grp.id);
            if (userIdIndex >= 0) {
                let cloned = this.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);
                if (x.userOrgroupIds.length)
                    rulesAuthnChanged.push({ previous: cloned, item: x });
                else {
                    arr.splice(index, 1);
                    rulesAuthnDeleted.push({ previous: cloned });
                }
            }
        })
        //check authorization

        let rulesAuthzChanged: { previous: AuthorizationRule, item: AuthorizationRule }[] = [];
        let rulesAuthzDeleted: { previous: AuthorizationRule }[] = [];
        this.config.authorizationPolicy.rules.forEach((x, index, arr) => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == grp.id);
            if (userIdIndex >= 0) {
                let cloned = this.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);
                if (x.userOrgroupIds.length) {
                    rulesAuthzChanged.push({ previous: cloned, item: x });
                } else {
                    arr.splice(index, 1);
                    rulesAuthzDeleted.push({ previous: cloned })
                }
            }
        })

        usersChanged.forEach(x => {
            const trc = this.createTrackEvent(x.previous, x.item)
            this.emitEvent({ type: 'put', path: 'users', val: trc.after, before: trc.after })
        })

        rulesAuthnChanged.forEach(x => {
            const trc = this.createTrackEvent(x.previous, x.item);
            this.emitEvent({ type: 'put', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before })
        })
        rulesAuthnDeleted.forEach(x => {
            const trc = this.createTrackEvent(x.previous);
            this.emitEvent({ type: 'del', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before })
        })

        rulesAuthzChanged.forEach(x => {
            const trc = this.createTrackEvent(x.previous, x.item)
            this.emitEvent({ type: 'put', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before })
        })
        rulesAuthzDeleted.forEach(x => {
            const trc = this.createTrackEvent(x.previous)
            this.emitEvent({ type: 'del', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before })
        })

        const trc = this.createTrackEvent(grp);

        this.emitEvent({ type: 'del', path: 'groups', val: trc.after, before: trc.before })



    }

    async deleteGroup(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.groups.findIndex(x => x.id == id);
        const group = this.config.groups.find(x => x.id == id);
        if (indexId >= 0 && group) {
            this.config.groups.splice(indexId, 1);
            this.triggerDeleteGroup(group)
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(group);


    }

    async saveGroup(group: Group) {
        this.isReady(); this.isWritable();
        let findedIndex = this.config.groups.findIndex(x => x.id == group.id);
        let finded = findedIndex >= 0 ? this.config.groups[findedIndex] : null;
        const cloned = this.clone(group);
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.groups.push(cloned);
            findedIndex = this.config.groups.length - 1;

            const trc = this.createTrackEvent(finded, this.config.groups[findedIndex]);
            this.emitEvent({ type: 'put', path: 'groups', val: trc.after, before: trc.before })
        } else {
            this.config.groups[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            const trc = this.createTrackEvent(finded, this.config.groups[findedIndex]);
            this.emitEvent({ type: 'put', path: 'groups', val: trc.after, before: trc.before })
        }
        await this.saveConfigToFile();
        return this.createTrackEvent(finded, this.config.groups[findedIndex]);
    }


    //// service entity
    async getService(id: string): Promise<Service | undefined> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.services.find(x => x.id == id));

    }
    async getServiceCount() {
        this.isReady(); this.isReadable();
        return this.config.services.length;
    }

    async getServicesBy(query?: string, networkIds?: string[], ids?: string[]) {
        this.isReady(); this.isReadable();
        const search = query?.toLowerCase();
        let services = !search ? this.config.services : this.config.services.filter(x => {
            if (x.labels?.length && x.labels.find(y => y.toLowerCase().includes(search)))
                return true;
            if (x.name?.toLowerCase().includes(search))
                return true;
            if (x.hosts?.some(x => x.host?.toLocaleLowerCase().includes(search)))
                return true;
            if (x.ports?.some(y => y.port.toString().includes(search)))
                return true;

            if (x.protocol?.toLocaleLowerCase().includes(search))
                return true;

            return false;
        });
        if (networkIds && networkIds.length)
            services = services.filter(x => networkIds.includes(x.networkId));
        if (ids && ids.length)
            services = services.filter(x => ids.includes(x.id));

        services.sort((a, b) => {
            return a.name.localeCompare(b.name)
        })
        return services.map(x => this.clone(x));
    }

    async getServicesByNetworkId(networkId: string) {
        this.isReady(); this.isReadable();
        return this.config.services.filter(x => x.networkId == networkId).map(x => this.clone(x));
    }

    //// service entity
    async getServicesAll(): Promise<Service[]> {
        this.isReady(); this.isReadable();
        return this.config.services.map(x => this.clone(x));

    }


    /**
     * @summary create tracking items
     * @param previous 
     * @param item 
     * @returns 
     */
    createTrackEvent<T>(previous: T, item?: T): { before?: NonNullable<T>, after?: NonNullable<T> } {
        return {
            before: Util.isUndefinedOrNull(previous) ? undefined : this.clone(previous),
            after: Util.isUndefinedOrNull(item) ? undefined : this.clone(item)
        } as { before?: NonNullable<T>, after?: NonNullable<T> }
    }
    /**
     * @summary tracks an array object, if something changes
     */
    createTrackIndexEvent(item: any, iBefore: number, iAfter: number) {
        return {
            item: this.clone(item),
            iBefore: iBefore,
            iAfter: iAfter
        }
    }

    protected async triggerServiceDeleted(svc: Service) {

        //check authorization
        let rulesAuthzChanged = this.config.authorizationPolicy.rules.filter(x => x.serviceId == svc.id);
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => x.serviceId != svc.id);

        rulesAuthzChanged.forEach(x => {
            const trc = this.createTrackEvent(x);
            this.emitEvent({ type: 'del', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before })
        })

        const trc = this.createTrackEvent(svc)
        this.emitEvent({ type: 'del', path: 'services', val: trc.after, before: trc.before })

    }

    async deleteService(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.services.findIndex(x => x.id == id);
        const svc = this.config.services.find(x => x.id == id);
        if (indexId >= 0 && svc) {
            this.config.services.splice(indexId, 1);
            await this.triggerServiceDeleted(svc);
            await this.saveConfigToFile();

        }
        return this.createTrackEvent(svc);//return deleted service for log if exists
    }

    async saveService(service: Service) {
        this.isReady(); this.isWritable();
        let findedIndex = this.config.services.findIndex(x => x.id == service.id);
        let finded = findedIndex >= 0 ? this.config.services[findedIndex] : null;
        const cloned = this.clone(service);
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.services.push(cloned);
            findedIndex = this.config.services.length - 1;
            const trc = this.createTrackEvent(finded, this.config.services[findedIndex]);
            this.emitEvent({ type: 'put', path: 'services', val: trc.after, before: trc.before })
        } else {
            this.config.services[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            const trc = this.createTrackEvent(finded, this.config.services[findedIndex])
            this.emitEvent({ type: 'put', path: 'services', val: trc.after, before: trc.before })
        }
        await this.saveConfigToFile();

        return this.createTrackEvent(finded, this.config.services[findedIndex]);
    }


    //authenticaton  policy

    async saveAuthenticationPolicyRule(arule: AuthenticationRule) {
        this.isReady(); this.isWritable();
        const cloned = this.clone(arule);
        let ruleIndex = this.config.authenticationPolicy.rules.findIndex(x => x.id == arule.id);
        let previous = this.config.authenticationPolicy.rules[ruleIndex];

        if (ruleIndex >= 0) {
            cloned.updateDate = new Date().toISOString();
            this.config.authenticationPolicy.rules[ruleIndex] = cloned;
            const trc = this.createTrackEvent(previous, this.config.authenticationPolicy.rules[ruleIndex])
            this.emitEvent({ type: 'put', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before })
        } else {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();

            this.config.authenticationPolicy.rules.push(cloned);
            this.config.authenticationPolicy.rulesOrder.push(cloned.id);
            ruleIndex = this.config.authenticationPolicy.rules.length - 1;
            const trc = this.createTrackEvent(previous, this.config.authenticationPolicy.rules[ruleIndex]);
            this.emitEvent({ type: 'put', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before })
        }


        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.authenticationPolicy.rules[ruleIndex])
    }
    async getAuthenticationPolicy() {
        this.isReady(); this.isReadable();
        return this.clone(this.config.authenticationPolicy);
    }

    async getAuthenticationPolicyRule(id: string) {
        this.isReady(); this.isReadable();
        const rule = this.config.authenticationPolicy.rules.find(x => x.id == id);
        return this.clone(rule);
    }
    async getAuthenticationPolicyRuleCount() {
        this.isReady(); this.isReadable();
        return this.config.authenticationPolicy.rules.length;
    }

    async deleteAuthenticationPolicyRule(id: string) {
        this.isReady(); this.isWritable();
        const ruleIndex = this.config.authenticationPolicy.rules.findIndex(x => x.id == id);
        const rule = this.config.authenticationPolicy.rules.find(x => x.id == id);
        if (ruleIndex >= 0 && rule) {
            this.config.authenticationPolicy.rules.splice(ruleIndex, 1);
            this.config.authenticationPolicy.rulesOrder.splice(ruleIndex, 1);
            const trc = this.createTrackEvent(rule);
            this.emitEvent({
                type: 'del', path: 'authenticationPolicy/rules',
                val: trc.after, before: trc.before
            })

            await this.saveConfigToFile();
        }
        return this.createTrackEvent(rule);
    }

    async updateAuthenticationRulePos(id: string, previous: number, next: string, index: number) {
        this.isReady(); this.isWritable();
        const currentRule = this.config.authenticationPolicy.rules[previous];
        if (currentRule.id != id)
            throw new RestfullException(409, ErrorCodes.ErrConflictData, ErrorCodes.ErrConflictData, "no rule");
        if (previous < 0)
            throw new Error('array index can be negative');

        if (this.config.authenticationPolicy.rulesOrder[index] != next)
            throw new RestfullException(409, ErrorCodes.ErrConflictData, ErrorCodes.ErrConflictData, "no rule");

        this.config.authenticationPolicy.rules.splice(previous, 1);
        this.config.authenticationPolicy.rules.splice(index, 0, currentRule);
        this.config.authenticationPolicy.rulesOrder.splice(previous, 1);
        this.config.authenticationPolicy.rulesOrder.splice(index, 0, currentRule.id);

        const trc = this.createTrackIndexEvent(currentRule, previous, index);
        this.emitEvent({
            type: 'put', path: 'authenticationPolicy/rulesOrder',
            val: trc.iAfter, before: trc.iBefore

        })

        return this.createTrackIndexEvent(currentRule, previous, index);

    }
    //authorization policy

    async saveAuthorizationPolicyRule(arule: AuthorizationRule) {
        this.isReady(); this.isWritable();
        const cloned = this.clone(arule);
        let ruleIndex = this.config.authorizationPolicy.rules.findIndex(x => x.id == arule.id);
        const previous = this.config.authorizationPolicy.rules[ruleIndex];
        if (ruleIndex >= 0) {
            cloned.updateDate = new Date().toISOString();
            this.config.authorizationPolicy.rules[ruleIndex] = cloned;
            const trc = this.createTrackEvent(previous, this.config.authorizationPolicy.rules[ruleIndex]);
            this.emitEvent({ type: 'put', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before })
        } else {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.authorizationPolicy.rules.push(cloned);
            this.config.authorizationPolicy.rulesOrder.push(cloned.id);
            ruleIndex = this.config.authorizationPolicy.rules.length - 1;
            const trc = this.createTrackEvent(previous, this.config.authorizationPolicy.rules[ruleIndex])
            this.emitEvent({ type: 'put', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before })
        }


        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.authorizationPolicy.rules[ruleIndex]);

    }
    async getAuthorizationPolicy() {
        this.isReady(); this.isReadable();
        return this.clone(this.config.authorizationPolicy);
    }

    async getAuthorizationPolicyRule(id: string) {
        this.isReady(); this.isReadable();
        const rule = this.config.authorizationPolicy.rules.find(x => x.id == id);
        return this.clone(rule);
    }

    async getAuthorizationPolicyRuleCount() {
        this.isReady(); this.isReadable();
        return this.config.authorizationPolicy.rules.length;
    }
    async deleteAuthorizationPolicyRule(id: string) {
        this.isReady(); this.isWritable();
        const ruleIndex = this.config.authorizationPolicy.rules.findIndex(x => x.id == id);
        const rule = this.config.authorizationPolicy.rules.find(x => x.id == id);
        if (ruleIndex >= 0 && rule) {
            this.config.authorizationPolicy.rules.splice(ruleIndex, 1);
            this.config.authorizationPolicy.rulesOrder.splice(ruleIndex, 1);

            const trc = this.createTrackEvent(rule);
            this.emitEvent({ type: 'del', path: 'authorizationPolicy/rules', val: trc.after, before: trc.before })

            await this.saveConfigToFile();
        }
        return this.createTrackEvent(rule);
    }

    async updateAuthorizationRulePos(id: string, previous: number, next: string, index: number) {
        this.isReady(); this.isWritable();
        const currentRule = this.config.authorizationPolicy.rules[previous];
        if (currentRule.id != id)
            throw new RestfullException(409, ErrorCodes.ErrConflictData, ErrorCodes.ErrConflictData, "no rule");
        if (previous < 0)
            throw new Error('array index can be negative');


        this.config.authorizationPolicy.rules.splice(previous, 1);
        this.config.authorizationPolicy.rules.splice(index, 0, currentRule);
        this.config.authorizationPolicy.rulesOrder.splice(previous, 1);
        this.config.authorizationPolicy.rulesOrder.splice(index, 0, currentRule.id);

        const trc = this.createTrackIndexEvent(currentRule, previous, index);
        this.emitEvent({ type: 'put', path: 'authorizationPolicy/rules', val: trc.iAfter, before: trc.iBefore })
        return this.createTrackIndexEvent(currentRule, previous, index);

    }

    async setES(conf: ESSetting) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(conf);
        const prev = this.config.es;
        this.config.es = cloned;
        const trc = this.createTrackEvent(prev, this.config.es)
        this.emitEvent({ type: 'put', path: 'es', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.es);
    }
    async getES() {
        this.isReady(); this.isReadable();
        const config = this.clone(this.config.es);
        return config;
    }

    async getConfig(config?: Config) {

    }
    async setConfig(cfg: Config) {

    }
    ///////// ip intelligence /////////////////////////////////////


    // new ip intelligence


    async getIpIntelligenceSources() {
        this.isReady(); this.isReadable();
        const config = this.clone(this.config.ipIntelligence.sources);
        return config;
    }
    async getIpIntelligenceSource(id: string) {
        this.isReady(); this.isReadable();
        const source = this.config.ipIntelligence.sources.find(x => x.id == id);
        if (!source) {
            return source;
        }
        return this.clone(source);
    }
    async saveIpIntelligenceSource(source: IpIntelligenceSource) {
        this.isReady(); this.isReadable();
        let findedIndex = this.config.ipIntelligence.sources.findIndex(x => x.id == source.id);
        let finded = this.config.ipIntelligence.sources[findedIndex];
        const cloned = this.clone(source);
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.ipIntelligence.sources.push(cloned);
            findedIndex = this.config.ipIntelligence.sources.length - 1;
            const trc = this.createTrackEvent(finded, this.config.ipIntelligence.sources[findedIndex]);
            this.emitEvent({ type: 'put', path: 'ipIntelligence/sources', val: trc.after, before: trc.before });
        } else {
            this.config.ipIntelligence.sources[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            const trc = this.createTrackEvent(finded, this.config.ipIntelligence.sources[findedIndex])
            this.emitEvent({ type: 'put', path: 'ipIntelligence/sources', val: trc.after, before: trc.before });
        }
        await this.saveConfigToFile();
        return this.createTrackEvent(finded, this.config.ipIntelligence.sources[findedIndex]);
    }
    async deleteIpIntelligenceSource(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.ipIntelligence.sources.findIndex(x => x.id == id);
        const source = this.config.ipIntelligence.sources.find(x => x.id == id);
        if (indexId >= 0 && source) {
            this.config.ipIntelligence.sources.splice(indexId, 1);
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(source)

    }



    async getIpIntelligenceLists() {
        this.isReady(); this.isReadable();
        const config = this.clone(this.config.ipIntelligence.lists);
        return config;
    }
    async getIpIntelligenceList(id: string) {
        this.isReady(); this.isReadable();
        const source = this.config.ipIntelligence.lists.find(x => x.id == id);
        if (!source) {
            return source;
        }
        return this.clone(source);
    }
    async saveIpIntelligenceList(list: IpIntelligenceList) {
        this.isReady(); this.isReadable();
        let findedIndex = this.config.ipIntelligence.lists.findIndex(x => x.id == list.id);
        let finded = this.config.ipIntelligence.lists[findedIndex];
        const cloned = this.clone(list);
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.ipIntelligence.lists.push(cloned);
            findedIndex = this.config.ipIntelligence.lists.length - 1;
            const trc = this.createTrackEvent(finded, this.config.ipIntelligence.lists[findedIndex]);
            this.emitEvent({ type: 'put', path: 'ipIntelligence/lists', val: trc.after, before: trc.before });
        } else {
            this.config.ipIntelligence.lists[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            const trc = this.createTrackEvent(finded, this.config.ipIntelligence.lists[findedIndex])
            this.emitEvent({ type: 'put', path: 'ipIntelligence/lists', val: trc.after, before: trc.before });
        }
        await this.saveConfigToFile();
        return this.createTrackEvent(finded, this.config.ipIntelligence.lists[findedIndex]);
    }
    async deleteIpIntelligenceList(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.ipIntelligence.lists.findIndex(x => x.id == id);
        const source = this.config.ipIntelligence.lists.find(x => x.id == id);
        if (indexId >= 0 && source) {
            this.config.ipIntelligence.lists.splice(indexId, 1);
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(source)

    }

    ///// device postures
    async getDevicePosture(id: string): Promise<DevicePosture | undefined> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.devicePostures.find(x => x.id == id));

    }
    async getDevicePostureCount() {
        this.isReady(); this.isReadable();
        return this.config.devicePostures.length;
    }

    async getDevicePosturesBySearch(query: string) {
        this.isReady(); this.isReadable();
        const search = query.toLowerCase();
        const devicePostures = this.config.devicePostures.filter(x => {
            if (x.labels?.length && x.labels.find(y => y.toLowerCase().includes(search)))
                return true;
            if (x.name?.toLowerCase().includes(search))
                return true;

            return false;
        });
        return devicePostures.map(x => this.clone(x));
    }
    async getDevicePosturesAll() {
        this.isReady(); this.isReadable();
        return this.config.devicePostures.map(x => this.clone(x));
    }


    protected async triggerDeleteDevicePosture(dposture: DevicePosture) {


        //check policy authentication

        let rulesAuthnChanged: { previous: AuthenticationRule, item: AuthenticationRule }[] = [];
        this.config.authenticationPolicy.rules.forEach(x => {
            if (x.profile.device?.postures) {
                const postureIndex = x.profile.device?.postures.findIndex(x => x == dposture.id);
                if (postureIndex >= 0) {
                    let cloned = this.clone(x);
                    x.profile.device.postures.splice(postureIndex, 1);

                    rulesAuthnChanged.push({ previous: cloned, item: x });
                }
            }
        })




        rulesAuthnChanged.forEach(x => {
            const trc = this.createTrackEvent(x.previous, x.item);
            this.emitEvent({ type: 'put', path: 'authenticationPolicy/rules', val: trc.after, before: trc.before })
        })


        const trc = this.createTrackEvent(dposture);

        this.emitEvent({ type: 'del', path: 'devicePostures', val: trc.after, before: trc.before })



    }

    async deleteDevicePosture(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.devicePostures.findIndex(x => x.id == id);
        const devicePosture = this.config.devicePostures.find(x => x.id == id);
        if (indexId >= 0 && devicePosture) {
            this.config.devicePostures.splice(indexId, 1);
            this.triggerDeleteDevicePosture(devicePosture)
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(devicePosture);


    }

    async saveDevicePosture(dposture: DevicePosture) {
        this.isReady(); this.isWritable();
        let findedIndex = this.config.devicePostures.findIndex(x => x.id == dposture.id);
        let finded = findedIndex >= 0 ? this.config.devicePostures[findedIndex] : null;
        const cloned = this.clone(dposture);
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.devicePostures.push(cloned);
            findedIndex = this.config.devicePostures.length - 1;

            const trc = this.createTrackEvent(finded, this.config.devicePostures[findedIndex]);
            this.emitEvent({ type: 'put', path: 'devicePostures', val: trc.after, before: trc.before })
        } else {
            this.config.devicePostures[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            const trc = this.createTrackEvent(finded, this.config.devicePostures[findedIndex]);
            this.emitEvent({ type: 'put', path: 'devicePostures', val: trc.after, before: trc.before })
        }
        await this.saveConfigToFile();
        return this.createTrackEvent(finded, this.config.devicePostures[findedIndex]);
    }




    ///////// fqdn intelligence /////////////////////////////////////



    async getFqdnIntelligenceSources() {
        this.isReady(); this.isReadable();
        const config = this.clone(this.config.fqdnIntelligence.sources);
        return config;
    }
    async getFqdnIntelligenceSource(id: string) {
        this.isReady(); this.isReadable();
        const source = this.config.fqdnIntelligence.sources.find(x => x.id == id);
        if (!source) {
            return source;
        }
        return this.clone(source);
    }
    async saveFqdnIntelligenceSource(source: IpIntelligenceSource) {
        this.isReady(); this.isReadable();
        let findedIndex = this.config.fqdnIntelligence.sources.findIndex(x => x.id == source.id);
        let finded = this.config.fqdnIntelligence.sources[findedIndex];
        const cloned = this.clone(source);
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.fqdnIntelligence.sources.push(cloned);
            findedIndex = this.config.fqdnIntelligence.sources.length - 1;
            const trc = this.createTrackEvent(finded, this.config.fqdnIntelligence.sources[findedIndex]);
            this.emitEvent({ type: 'put', path: 'fqdnIntelligence/sources', val: trc.after, before: trc.before });
        } else {
            this.config.fqdnIntelligence.sources[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            const trc = this.createTrackEvent(finded, this.config.fqdnIntelligence.sources[findedIndex])
            this.emitEvent({ type: 'put', path: 'fqdnIntelligence/sources', val: trc.after, before: trc.before });
        }
        await this.saveConfigToFile();
        return this.createTrackEvent(finded, this.config.fqdnIntelligence.sources[findedIndex]);
    }
    async deleteFqdnIntelligenceSource(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.fqdnIntelligence.sources.findIndex(x => x.id == id);
        const source = this.config.fqdnIntelligence.sources.find(x => x.id == id);
        if (indexId >= 0 && source) {
            this.config.fqdnIntelligence.sources.splice(indexId, 1);
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(source)

    }



    async getFqdnIntelligenceLists() {
        this.isReady(); this.isReadable();
        const config = this.clone(this.config.fqdnIntelligence.lists);
        return config;
    }
    async getFqdnIntelligenceList(id: string) {
        this.isReady(); this.isReadable();
        const source = this.config.fqdnIntelligence.lists.find(x => x.id == id);
        if (!source) {
            return source;
        }
        return this.clone(source);
    }
    async saveFqdnIntelligenceList(list: FqdnIntelligenceList) {
        this.isReady(); this.isReadable();
        let findedIndex = this.config.fqdnIntelligence.lists.findIndex(x => x.id == list.id);
        let finded = this.config.fqdnIntelligence.lists[findedIndex];
        const cloned = this.clone(list);
        if (!finded) {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.fqdnIntelligence.lists.push(cloned);
            findedIndex = this.config.fqdnIntelligence.lists.length - 1;
            const trc = this.createTrackEvent(finded, this.config.fqdnIntelligence.lists[findedIndex]);
            this.emitEvent({ type: 'put', path: 'fqdnIntelligence/lists', val: trc.after, before: trc.before });
        } else {
            this.config.fqdnIntelligence.lists[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            const trc = this.createTrackEvent(finded, this.config.fqdnIntelligence.lists[findedIndex])
            this.emitEvent({ type: 'put', path: 'fqdnIntelligence/lists', val: trc.after, before: trc.before });
        }
        await this.saveConfigToFile();
        return this.createTrackEvent(finded, this.config.fqdnIntelligence.lists[findedIndex]);
    }
    async deleteFqdnIntelligenceList(id: string) {
        this.isReady(); this.isWritable();
        const indexId = this.config.fqdnIntelligence.lists.findIndex(x => x.id == id);
        const source = this.config.fqdnIntelligence.lists.find(x => x.id == id);
        if (indexId >= 0 && source) {
            this.config.fqdnIntelligence.lists.splice(indexId, 1);
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(source)

    }
    async getHttpToHttpsRedirect(): Promise<boolean> {
        this.isReady(); this.isReadable();
        return this.config.httpToHttpsRedirect ? true : false;
    }

    async setHttpToHttpsRedirect(val: boolean) {
        this.isReady(); this.isWritable();
        let previous = this.config.httpToHttpsRedirect;
        this.config.httpToHttpsRedirect = val;
        const trc = this.createTrackEvent(previous, this.config.httpToHttpsRedirect)
        this.emitEvent({ type: 'put', path: 'httpToHttpsRedirect', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.httpToHttpsRedirect);
    }

    /// brand
    async getBrand(): Promise<BrandSetting> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.brand);
    }
    async setBrand(brand: BrandSetting | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(brand);
        let prev = this.config.brand;
        this.config.brand = {
            ...cloned
        }
        const trc = this.createTrackEvent(prev, this.config.brand);
        this.emitEvent({ type: 'put', path: 'brand', val: trc.after, before: trc.before })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.brand);
    }







}
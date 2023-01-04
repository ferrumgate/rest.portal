import fs from "fs";
import { logger } from "../common";
import { Config, ConfigEvent } from "../model/config";
import yaml from 'yaml';
import { Util } from "../util";
import { User } from "../model/user";
import { EmailSettings } from "../model/emailSettings";
import { LogoSettings } from "../model/logoSettings";
import { Captcha } from "../model/captcha";
import { SSLCertificate } from "../model/sslCertificate";
import { SSHCertificate } from "../model/sshCertificate";
import { ErrorCodes, RestfullException } from "../restfullException";
import { AuthCommon, AuthLdap, AuthLocal, AuthOAuth, AuthSaml, AuthSettings, BaseLdap, BaseOAuth, BaseSaml } from "../model/authSettings";
import { RBAC, RBACDefault, Role } from "../model/rbac";
import { HelperService } from "./helperService";
import { Gateway, Network } from "../model/network";
import { Group } from "../model/group";
import { Service } from "../model/service";
import { AuthenticationRule } from "../model/authenticationPolicy";
import { AuthorizationRule } from "../model/authorizationPolicy";
import EventEmitter from "node:events";






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

        this.secretKey = encryptKey;
        if (configFile)
            this.configfile = configFile;
        this.config = {
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
            jwtSSLCertificate: {},
            sslCertificate: {},
            caSSLCertificate: {},
            domain: 'ferrumgate.local',
            url: 'https://secure.yourdomain.com',
            email: this.createDefaultEmail(),
            logo: {},
            auth: {
                common: {},
                local: this.createAuthLocal(),
                ldap: { providers: [] },
                oauth: { providers: [] },
                saml: { providers: [] }

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
            authorizationPolicy: { rules: [], rulesOrder: [] }


        }
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
        if (process.env.LIMITED_MODE == 'true') {
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
        }



    }
    async init() {
        await this.createCerts();
    }
    async start() {
        await this.init();

    }
    protected async createCerts() {

        if (!(await this.getJWTSSLCertificate()).privateKey) {
            const { privateKey, publicKey } = await Util.createSelfSignedCrt("ferrumgate.com");
            await this.setJWTSSLCertificate({
                privateKey: privateKey,
                publicKey: publicKey,
            });
        }
        //create ca ssl certificate if not exists;
        if (!(await this.getCASSLCertificate()).privateKey) {
            const { privateKey, publicKey } = await Util.createSelfSignedCrt("ferrumgate.local");
            await this.setSSLCertificate({
                privateKey: privateKey,
                publicKey: publicKey,
            });
        }
        //create ssl certificates if not exists
        if (!(await this.getSSLCertificate()).privateKey) {
            const { privateKey, publicKey } = await Util.createSelfSignedCrt("secure.ferrumgate.local");
            await this.setSSLCertificate({
                privateKey: privateKey,
                publicKey: publicKey,
            });
        }
    }
    async stop() {

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



    protected createDefaultEmail(): EmailSettings {
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
    emitEvent(event: ConfigEvent) {
        this.events.emit('changed', event);
        //return event;
    }

    /* private writeAsset(name: string, image: string) {
         const type = image.substring(image.indexOf('/') + 1, image.indexOf(';'));
         const base64Image = image.split(';base64,').pop();
         let path = `./dassets/img`;
         fs.mkdirSync(path, { recursive: true });
         if (type && base64Image) {
             path = `${path}/${name}.${type}`;
             fs.writeFileSync(path, base64Image, { encoding: 'base64' });
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
                const decrpted = Util.decrypt(this.secretKey, content, 'base64');
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
            const encrypted = Util.encrypt(this.secretKey, str, 'base64');
            fs.writeFileSync(this.configfile, encrypted, { encoding: 'utf-8' });
        }
        await this.saveLastUpdateTime();


    }
    async saveConfigToString() {
        const str = yaml.stringify(this.config);
        if (process.env.NODE_ENV == 'development') {
            return str;
        } else {
            const encrypted = Util.encrypt(this.secretKey, str, 'base64');
            return encrypted;
        }
    }

    protected deleteUserSensitiveData(user?: User) {
        delete user?.apiKey;
        delete user?.twoFASecret;
        delete user?.password;
        //delete user?.roleIds;// is this necessary
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
    async getUserByApiKey(key: string): Promise<User | undefined> {
        this.isReady(); this.isReadable();
        if (!key) return undefined;
        let user = this.clone(this.config.users.find(x => x.apiKey == key));
        this.deleteUserSensitiveData(user);
        return user;
    }
    async getUserById(id: string): Promise<User | undefined> {
        this.isReady(); this.isReadable();
        let user = this.clone(this.config.users.find(x => x.id == id));
        this.deleteUserSensitiveData(user);
        return user;
    }
    async getUser(id: string) {
        this.isReady(); this.isReadable();
        return await this.getUserById(id);
    }

    async getUsersBy(page: number = 0, pageSize: number = 0, search?: string,
        ids?: string[], groupIds?: string[], roleIds?: string[],
        is2FA?: boolean, isVerified?: boolean, isLocked?: boolean,
        isEmailVerified?: boolean, isOnlyApiKey?: boolean) {
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

            })
        if (ids && ids.length)
            filteredUsers = filteredUsers.filter(x => ids.includes(x.id));
        if (groupIds && groupIds.length)
            filteredUsers = filteredUsers.filter(x => Util.isArrayElementExist(x.groupIds, groupIds));
        if (roleIds && roleIds.length)
            filteredUsers = filteredUsers.filter(x => Util.isArrayElementExist(x.roleIds, roleIds));
        if (!Util.isUndefinedOrNull(is2FA))
            filteredUsers = filteredUsers.filter(x => Boolean(x.is2FA) == is2FA)
        if (!Util.isUndefinedOrNull(isVerified))
            filteredUsers = filteredUsers.filter(x => Boolean(x.isVerified) == isVerified)
        if (!Util.isUndefinedOrNull(isLocked))
            filteredUsers = filteredUsers.filter(x => Boolean(x.isLocked) == isLocked)

        if (!Util.isUndefinedOrNull(isEmailVerified))
            filteredUsers = filteredUsers.filter(x => Boolean(x.isEmailVerified) == isEmailVerified)

        if (!Util.isUndefinedOrNull(isOnlyApiKey))
            filteredUsers = filteredUsers.filter(x => Boolean(x.isOnlyApiKey) == isOnlyApiKey)

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
    async getUserSensitiveData(id: string) {
        this.isReady(); this.isReadable();
        let user = this.clone(this.config.users.find(x => x.id == id)) as User;
        return { twoFASecret: user?.twoFASecret };
    }

    protected async triggerUserDeleted(user: User) {
        //check policy authentication

        let rulesAuthnChanged: { previous: AuthenticationRule, item: AuthenticationRule }[] = [];
        this.config.authenticationPolicy.rules.forEach(x => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == user.id);
            if (userIdIndex >= 0) {
                const prev = this.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);
                rulesAuthnChanged.push({ previous: prev, item: x });
            }
        })
        //check authorization

        let rulesAuthzChanged: { previous: AuthorizationRule, item: AuthorizationRule }[] = [];
        this.config.authorizationPolicy.rules.forEach(x => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == user.id);
            if (userIdIndex >= 0) {
                const prev = this.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);
                rulesAuthzChanged.push({ previous: prev, item: x });
            }
        })

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

            this.emitEvent({ type: 'saved', path: '/users', data: this.createTrackEvent(finded, this.config.users[findedIndex]) })

        }
        else {
            cloned.id = finded.id;//security

            this.config.users[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            this.emitEvent({ type: 'updated', path: '/users', data: this.createTrackEvent(finded, this.config.users[findedIndex]) })

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
        this.emitEvent({ type: 'updated', path: '/users', data: this.createTrackEvent(prev, finded) })
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
        this.emitEvent({ type: 'updated', path: '/captcha', data: this.createTrackEvent(prev, this.config.captcha) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.captcha);
    }

    async getJWTSSLCertificate(): Promise<SSLCertificate> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.jwtSSLCertificate);
    }

    async setJWTSSLCertificate(cert: SSLCertificate | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(cert);
        const prev = this.config.jwtSSLCertificate;
        this.config.jwtSSLCertificate = {
            ...this.config.jwtSSLCertificate,
            ...cloned
        }
        this.emitEvent({ type: 'updated', path: '/jwtSSLCertificate', data: this.createTrackEvent(prev, this.config.jwtSSLCertificate) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.jwtSSLCertificate);
    }

    async getSSLCertificate(): Promise<SSLCertificate> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.sslCertificate);
    }

    async setSSLCertificate(cert: SSLCertificate | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(cert);
        const prev = this.config.sslCertificate;
        this.config.sslCertificate = {
            ...this.config.sslCertificate,
            ...cloned
        }
        this.emitEvent({ type: 'updated', path: '/sslCertificate', data: this.createTrackEvent(prev, this.config.sslCertificate) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.sslCertificate);
    }

    async getCASSLCertificate(): Promise<SSLCertificate> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.caSSLCertificate);
    }
    async getCASSLCertificatePublic(): Promise<string | null | undefined> {
        this.isReady(); this.isReadable();
        return this.config.caSSLCertificate.publicKey;
    }

    async setCASSLCertificate(cert: SSLCertificate | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(cert);
        const prev = this.config.caSSLCertificate;
        this.config.caSSLCertificate = {
            ...this.config.caSSLCertificate,
            ...cloned
        }
        this.emitEvent({ type: 'updated', path: '/caSSLCertificate', data: this.createTrackEvent(prev, this.config.sslCertificate) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.caSSLCertificate);
    }


    async getEmailSettings(): Promise<EmailSettings> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.email);
    }

    async setEmailSettings(options: EmailSettings) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(options);
        let prev = this.config.email;
        this.config.email = {
            ...this.config.email,
            ...cloned
        }
        this.emitEvent({ type: 'updated', path: '/email', data: this.createTrackEvent(prev, this.config.email) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.email);
    }

    async getLogo(): Promise<LogoSettings> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.logo);
    }
    async setLogo(logo: LogoSettings | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(logo);
        let prev = this.config.logo;
        this.config.logo = {
            ...this.config.logo,
            ...cloned
        }
        this.emitEvent({ type: 'updated', path: '/logo', data: this.createTrackEvent(prev, this.config.logo) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.logo);
    }

    async getAuthSettings(): Promise<AuthSettings> {
        this.isReady(); this.isReadable();
        return this.clone(this.config.auth);
    }
    /* // needs a sync version
    getAuthSettingsSync(): AuthSettings {
        return this.clone(this.config.auth);
    } */

    async setAuthSettings(option: AuthSettings | {}) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(option);
        let prev = this.config.auth;
        this.config.auth = {
            ...this.config.auth,
            ...cloned
        }
        this.emitEvent({ type: 'updated', path: '/auth', data: this.createTrackEvent(prev, this.config.auth) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.auth);
    }
    async setAuthSettingsCommon(common: AuthCommon) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(common);
        let prev = this.config.auth.common;
        this.config.auth.common = cloned;
        this.emitEvent({ type: 'updated', path: '/auth/common', data: this.createTrackEvent(prev, this.config.auth.common) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.auth.common);
    }
    async getAuthSettingsCommon() {
        this.isReady(); this.isReadable();
        const common = this.clone(this.config.auth.common);
        return common;
    }


    async setAuthSettingsLocal(local: AuthLocal) {
        this.isReady(); this.isWritable();
        let cloned = this.clone(local);
        const prev = this.config.auth.local;
        this.config.auth.local = cloned;
        this.emitEvent({ type: 'updated', path: '/auth/local', data: this.createTrackEvent(prev, this.config.auth.local) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.auth.local);
    }
    async getAuthSettingsLocal() {
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
            this.emitEvent({ type: 'saved', path: '/auth/oauth/providers', data: this.createTrackEvent(previous, this.config.auth.oauth.providers[index]) })
        }
        else {
            this.config.auth.oauth.providers[index] = {
                ...cloned
            }
            this.emitEvent({ type: 'updated', path: '/auth/oauth/providers', data: this.createTrackEvent(previous, this.config.auth.oauth.providers[index]) })
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
            this.emitEvent({ type: 'deleted', path: '/auth/oauth/providers', data: this.createTrackEvent(provider) })
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
            this.emitEvent({ type: 'saved', path: '/auth/ldap/providers', data: this.createTrackEvent(this.config.auth.ldap.providers[index]) })
        }
        else {
            this.config.auth.ldap.providers[index] = {
                ...cloned
            }
            this.emitEvent({ type: 'updated', path: '/auth/ldap/providers', data: this.createTrackEvent(this.config.auth.ldap.providers[index]) })
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
            this.emitEvent({ type: 'deleted', path: '/auth/ldap/providers', data: this.createTrackEvent(provider) })
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
            this.emitEvent({ type: 'saved', path: '/auth/saml/providers', data: this.createTrackEvent(this.config.auth.saml.providers[index]) })
        }
        else {
            this.config.auth.saml.providers[index] = {
                ...cloned
            }
            this.emitEvent({ type: 'updated', path: '/auth/saml/providers', data: this.createTrackEvent(previous, this.config.auth.saml.providers[index]) })
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
            this.emitEvent({ type: 'deleted', path: '/auth/saml/providers', data: this.createTrackEvent(provider) })
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
            this.emitEvent({ type: "updated", path: '/gateways', data: this.createTrackEvent(previous, x) })
        });

        //////////services

        let deleteServices = this.config.services.filter(x => x.networkId == net.id);
        this.config.services = this.config.services.filter(x => x.networkId != net.id);
        deleteServices.forEach(x => {
            this.emitEvent({ type: 'deleted', path: '/services', data: this.createTrackEvent(x) });
        })

        //// policy authorization
        let deleteAuthorizationRules = this.config.authorizationPolicy.rules.filter(x => x.networkId == net.id);
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => x.networkId != net.id);
        deleteAuthorizationRules.forEach(x => {
            this.emitEvent({ type: 'deleted', path: '/authorizationPolicy/rules', data: this.createTrackEvent(x) });
        })
        //check one more
        let deleteServicesId = deleteServices.map(x => x.id);
        let deleteAuthorizatonRules2 = this.config.authorizationPolicy.rules.filter(x => deleteServicesId.includes(x.serviceId));
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => !deleteServicesId.includes(x.serviceId));
        deleteAuthorizatonRules2.forEach(x => {
            this.emitEvent({ type: 'deleted', path: '/authorizationPolicy/rules', data: this.createTrackEvent(x) });
        })
        if (deleteAuthorizationRules.length || deleteAuthorizatonRules2.length) {
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy' });
        }

        //policy authentication
        let deleteAuthenticationRules = this.config.authenticationPolicy.rules.filter(x => x.networkId == net.id);
        this.config.authenticationPolicy.rules = this.config.authenticationPolicy.rules.filter(x => x.networkId != net.id);
        deleteAuthenticationRules.forEach(x => {
            this.emitEvent({ type: 'deleted', path: '/authenticationPolicy/rules', data: this.createTrackEvent(x) });
        })
        if (deleteAuthenticationRules.length) {
            this.emitEvent({ type: 'updated', path: '/authenticationPolicy' });
        }

        this.emitEvent({ type: 'deleted', path: '/networks', data: this.createTrackEvent(net) });

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
            this.emitEvent({ type: 'saved', path: '/networks', data: this.createTrackEvent(finded, this.config.networks[findedIndex]) });
        } else {
            this.config.networks[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            this.emitEvent({ type: 'updated', path: '/networks', data: this.createTrackEvent(finded, this.config.networks[findedIndex]) });
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
        this.emitEvent({ type: 'updated', path: '/domain', data: this.createTrackEvent(previous, this.config.domain) })
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
        this.emitEvent({ type: 'deleted', path: '/gateways', data: this.createTrackEvent(gate) });
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
            this.emitEvent({ type: 'saved', path: '/gateways', data: this.createTrackEvent(finded, this.config.gateways[findedIndex]) });
        } else {
            this.config.gateways[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            this.emitEvent({ type: 'saved', path: '/gateways', data: this.createTrackEvent(finded, this.config.gateways[findedIndex]) });
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
        this.emitEvent({ type: 'updated', path: '/url', data: this.createTrackEvent(previous, this.config.url) })
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
        this.emitEvent({ type: 'updated', path: '/isConfigured', data: this.createTrackEvent(previous, this.config.isConfigured) })
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
        this.config.authenticationPolicy.rules.forEach(x => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == grp.id);
            if (userIdIndex >= 0) {
                let cloned = this.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);

                rulesAuthnChanged.push({ previous: cloned, item: x });
            }
        })
        //check authorization

        let rulesAuthzChanged: { previous: AuthorizationRule, item: AuthorizationRule }[] = [];
        this.config.authorizationPolicy.rules.forEach(x => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == grp.id);
            if (userIdIndex >= 0) {
                let cloned = this.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);

                rulesAuthzChanged.push({ previous: cloned, item: x });
            }
        })

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
            this.emitEvent({ type: 'saved', path: '/groups', data: this.createTrackEvent(finded, this.config.groups[findedIndex]) })
        } else {
            this.config.groups[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            this.emitEvent({ type: 'updated', path: '/groups', data: this.createTrackEvent(finded, this.config.groups[findedIndex]) })
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
            if (x.host?.toLocaleLowerCase().includes(search))
                return true;
            if (x.tcp?.toString().includes(search))
                return true;
            if (x.udp?.toString().includes(search))
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
    createTrackIndexEvent(item: any, iprevious: number, iitem: number) {
        return {
            item: this.clone(item),
            iBefore: iprevious,
            iAfter: iitem
        }
    }

    protected async triggerServiceDeleted(svc: Service) {

        //check authorization
        let rulesAuthzChanged = this.config.authorizationPolicy.rules.filter(x => x.serviceId == svc.id);
        this.config.authorizationPolicy.rules = this.config.authorizationPolicy.rules.filter(x => x.serviceId != svc.id);

        rulesAuthzChanged.forEach(x => {
            this.emitEvent({ type: 'deleted', path: '/authorizationPolicy/rules', data: this.createTrackEvent(x) })
        })
        if (rulesAuthzChanged.length)
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy' })

        this.emitEvent({ type: 'deleted', path: '/services', data: this.createTrackEvent(svc) })

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
            this.emitEvent({ type: 'saved', path: '/services', data: this.createTrackEvent(finded, this.config.services[findedIndex]) })
        } else {
            this.config.services[findedIndex] = {
                ...finded,
                ...cloned,
                updateDate: new Date().toISOString()
            }
            this.emitEvent({ type: 'updated', path: '/services', data: this.createTrackEvent(finded, this.config.services[findedIndex]) })
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
            this.emitEvent({ type: 'updated', path: '/authenticationPolicy/rules', data: this.createTrackEvent(previous, this.config.authenticationPolicy.rules[ruleIndex]) })
        } else {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();

            this.config.authenticationPolicy.rules.push(cloned);
            this.config.authenticationPolicy.rulesOrder.push(cloned.id);
            ruleIndex = this.config.authenticationPolicy.rules.length - 1;
            this.emitEvent({ type: 'saved', path: '/authenticationPolicy/rules', data: this.createTrackEvent(previous, this.config.authenticationPolicy.rules[ruleIndex]) })
        }

        this.emitEvent({ type: 'updated', path: '/authenticationPolicy' })
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
            this.emitEvent({ type: 'deleted', path: '/authenticationPolicy/rules', data: this.createTrackEvent(rule) })
            this.emitEvent({ type: 'updated', path: '/authenticationPolicy' })
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

        this.emitEvent({ type: 'updated', path: '/authenticationPolicy/rules', data: this.createTrackIndexEvent(currentRule, previous, index) })
        this.emitEvent({ type: 'updated', path: '/authenticationPolicy' })
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
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy/rules', data: this.createTrackEvent(previous, this.config.authorizationPolicy.rules[ruleIndex]) })
        } else {
            cloned.insertDate = new Date().toISOString();
            cloned.updateDate = new Date().toISOString();
            this.config.authorizationPolicy.rules.push(cloned);
            this.config.authorizationPolicy.rulesOrder.push(cloned.id);
            ruleIndex = this.config.authorizationPolicy.rules.length - 1;
            this.emitEvent({ type: 'saved', path: '/authorizationPolicy/rules', data: this.createTrackEvent(previous, this.config.authorizationPolicy.rules[ruleIndex]) })
        }

        this.emitEvent({ type: 'updated', path: '/authorizationPolicy' })
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
            this.emitEvent({ type: 'deleted', path: '/authorizationPolicy/rules', data: this.createTrackEvent(rule) })
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy' })
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

        this.emitEvent({ type: 'updated', path: '/authorizationPolicy/rules', data: this.createTrackIndexEvent(currentRule, previous, index) })
        this.emitEvent({ type: 'updated', path: '/authorizationPolicy' })
        return this.createTrackIndexEvent(currentRule, previous, index);

    }





}
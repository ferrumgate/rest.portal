import fs from "fs";
import { logger } from "../common";
import { Config } from "../model/config";
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
import { isAbsolute } from "path";
import { Group } from "../model/group";
import { util } from "chai";
import { Service } from "../model/service";



export class ConfigService {


    config: Config;
    protected configfile = `/etc/ferrumgate/config.yaml`;
    private secretKey = '';
    lastUpdateTime = '';
    /**
     *
     */
    constructor(encryptKey: string, configFile?: string) {
        if (!encryptKey)
            throw new Error('needs and encyption key with lenght 32');
        //default user
        const adminUser = HelperService.createUser('local-local', 'admin', 'default admin', 'ferrumgate');
        adminUser.isVerified = true;
        adminUser.roleIds = ['Admin'];

        //default network
        const defaultNetwork: Network = {
            id: Util.randomNumberString(16),
            name: 'default',
            labels: ['default'],
            clientNetwork: '100.64.0.0/16',
            serviceNetwork: '172.28.28.0/24'
        }

        this.secretKey = encryptKey;
        if (configFile)
            this.configfile = configFile;
        this.config = {
            isConfigured: 0,
            users: [
                adminUser
            ],
            groups: [],
            services: [],
            captcha: {},
            sshCertificate: {},
            jwtSSLCertificate: {},
            domain: 'ferrumgate.local',
            url: 'https://secure.yourdomain.com',
            email: {
                type: 'empty',
                fromname: '', pass: '', user: ''
            },
            logo: {},
            auth: {
                common: {},
                local: {
                    id: Util.randomNumberString(),
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
            },
            rbac: {
                roles: [RBACDefault.roleAdmin, RBACDefault.roleReporter, RBACDefault.roleUser],
                rights: [RBACDefault.rightAdmin, RBACDefault.rightReporter, RBACDefault.rightUser]
            },
            networks: [
                defaultNetwork
            ],
            gateways: []


        }
        //for testing
        if (process.env.NODE_ENV == 'development') {
            this.config.auth.oauth = {
                providers: [
                    {
                        baseType: 'oauth',
                        type: 'google',
                        id: Util.randomNumberString(),
                        name: 'Google/OAuth2',
                        tags: [],
                        clientId: '920409807691-jp82nth4a4ih9gv2cbnot79tfddecmdq.apps.googleusercontent.com',
                        clientSecret: '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',
                        isEnabled: true,
                        insertDate: new Date().toISOString(),
                        updateDate: new Date().toISOString()
                    },
                    {
                        baseType: 'oauth',
                        type: 'linkedin',
                        id: Util.randomNumberString(),
                        name: 'Linkedin/OAuth2',
                        tags: [],
                        clientId: '866dr29tuc5uy5',
                        clientSecret: '1E3DHw0FJFUsp1Um',
                        isEnabled: true,
                        insertDate: new Date().toISOString(),
                        updateDate: new Date().toISOString()
                    }
                ]
            }
            this.config.auth.ldap = {
                providers: [
                    {
                        baseType: 'ldap',
                        type: 'activedirectory',
                        id: Util.randomNumberString(),
                        name: 'Active Directory/Ldap',
                        tags: [],
                        host: 'ldap://192.168.88.254:389',
                        bindDN: 'CN=myadmin,CN=users,DC=testad,DC=local',
                        bindPass: 'Qa12345678',
                        searchBase: 'CN=users,DC=testad,DC=local',
                        groupnameField: 'memberOf',
                        usernameField: 'sAMAccountName',
                        isEnabled: true,
                        insertDate: new Date().toISOString(),
                        updateDate: new Date().toISOString()



                    },
                ]
            }

            this.config.auth.saml = {
                providers: [
                    {
                        baseType: 'saml',
                        type: 'auth0',
                        id: Util.randomNumberString(),
                        name: 'Auth0/Saml',
                        tags: [],
                        issuer: 'urn:dev-24wm8m7g.us.auth0.com',
                        loginUrl: 'https://dev-24wm8m7g.us.auth0.com/samlp/pryXTgkqDprtoGOg0RRH26ylKV0zg4xV',
                        fingerPrint: '96:39:6C:F6:ED:DF:07:30:F0:2E:45:95:02:B6:F6:68:B7:2C:11:37',
                        cert: `MIIDDTCCAfWgAwIBAgIJDVrH9KeUS+k8MA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi0yNHdtOG03Zy51cy5hdXRoMC5jb20wHhcNMjIxMDEwMjIzOTA2WhcNMzYwNjE4MjIzOTA2WjAkMSIwIAYDVQQDExlkZXYtMjR3bThtN2cudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA14riTBaUOB2+OZiEbpL5Cjy4MVl78Qi+Msi6IbmIs8nIGRav2hYsI3/mUex6+dCeqwoKCALByRySTEWhUCRWNsi86ae5CSsRikVBAPtEZqKBuoSthrjXUQT5/UBBOHc+EVUAiNrAEE1DBjpkFPkZfGk974ZukK8MyfliajjmFHGj23vwxJncxfx49kOEalz10M500MNldl+Kl628i//y3QiojTsNvPK4SiORFBR89DnWJoB/m6npsm9tkRKUFuYNedVEDru+8aac6LVrKkimDOUzXecAbCm7+td4rXCyV25cc3Pp0sHUYFYk4NoqzW6kJtddFcRQi+xo5JqcPjtunwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRZYMCT4GSETh+A4Ji9wWJxlcv53zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBACNDPiTHjyeFUIOTWnnZbTZil0nf+yrA6QVesV5+KJ9Ek+YgMrnZ4KdXEZZozUgiGsER1RjetWVYnv3AmEvML0CY/+xJu2bCfwQssSXFLQGdv079V81Mk2+Hz8gQgruLpJpfENQCsbWm3lXQP4F3avFw68HB62rr6jfyEIPb9n8rw/pj57y5ZILl97sb3QikgRh1pTEKVz05WLeHdGPE30QWklGDYxqv2/TbRWOUsdXjjbpE6pIfTUX5OLqGRbrtdHL9fHbhVOfqczALtneEjv5o/TpB3Jo2w9RU9AgMYwWT2Hpqop/fe9fyDQ+u5Hz7ZnADi/oktGBzm8/Y03WpkuM=`,
                        usernameField: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                        nameField: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                        isEnabled: true,
                        insertDate: new Date().toISOString(),
                        updateDate: new Date().toISOString()

                    },
                ]
            }

            this.config.email = { fromname: 'ferrumgate', type: 'google', user: 'ferrumgates@gmail.com', pass: 'nqquxankumksakon' };
            this.config.url = 'http://localhost:4200';
            this.config.captcha = {
                client: '6Lcw_scfAAAAABL_DeZVQNd-yNHp0CnNYE55rifH',
                server: '6Lcw_scfAAAAAFKwZuGa9vxuFF7ezh8ZtsQazdS0'
            }

            this.config.jwtSSLCertificate.privateKey = fs.readFileSync(`./ferrumgate.com.key`).toString();
            this.config.jwtSSLCertificate.publicKey = fs.readFileSync(`./ferrumgate.com.crt`).toString();
            if (fs.existsSync('/tmp/config.yaml') && !process.env.LOCAL_TEST)
                fs.rmSync('/tmp/config.yaml');
            const adminUser = HelperService.createUser('local-local', 'hamza1@hamzakilic.com', 'hamzaadmin', 'Deneme123');
            adminUser.isLocked = false;
            adminUser.isVerified = true;
            adminUser.roleIds = ['Admin'];
            adminUser.is2FA = true;
            adminUser.twoFASecret = 'GZTM2CLFZFQA4W3QSCOGG53QKU23CAZW';
            this.config.users.push(adminUser);

            const standartUser = HelperService.createUser('local-local', 'hamzauser@hamzakilic.com', 'hamzauser', 'Deneme123');
            standartUser.isLocked = false;
            standartUser.isVerified = true;
            standartUser.roleIds = ['User'];
            this.config.users.push(standartUser);

            // some networks
            let net: Network = {

                id: '312', name: 'ops', labels: ['deneme2'],
                serviceNetwork: '1.1.1.1/16',
                clientNetwork: '1.2.3.4/24'
            }
            this.config.networks.push(net);
            let gateways: Gateway[] = [
                { id: '123', networkId: net.id, name: 'blac1', labels: ['testme'], isEnabled: true },
                { id: '1234', networkId: net.id, name: 'blac2', labels: ['testme2'], isEnabled: true },
                { id: '12345', networkId: net.id, name: 'blac3', labels: ['testme3', 'testme2'], isEnabled: false },
                { id: '123456', networkId: '', name: 'blac4', labels: ['testme3'], isEnabled: false },
                { id: '1234567', networkId: '', name: 'blac5', labels: ['testme5'], isEnabled: false }
            ];
            gateways.forEach(x => this.config.gateways.push(x));

        }
        this.loadConfigFromFile();

        this.lastUpdateTime = new Date().toISOString();
    }
    resetUpdateTime() {
        this.lastUpdateTime = new Date(1900, 1, 1).toISOString();
    }
    setConfigPath(path: string) {
        this.configfile = path;
    }
    private writeAsset(name: string, image: string) {
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
    }

    loadConfigFromFile() {
        logger.info(`loading configuration from ${this.configfile}`);
        if (fs.existsSync(this.configfile)) {
            const content = fs.readFileSync(this.configfile, 'utf-8').toString();
            if (process.env.NODE_ENV == 'development') {
                this.config = yaml.parse(content);
            } else {
                const decrpted = Util.decrypt(this.secretKey, content);
                this.config = yaml.parse(decrpted);
            }
        }
        this.saveAssets();
    }
    saveConfigToFile() {
        const str = yaml.stringify(this.config);
        if (process.env.NODE_ENV == 'development') {

            fs.writeFileSync(this.configfile, str, { encoding: 'utf-8' });
        } else {
            const encrypted = Util.encrypt(this.secretKey, str);
            fs.writeFileSync(this.configfile, encrypted, { encoding: 'utf-8' });
        }
        this.lastUpdateTime = new Date().toISOString();
    }
    saveConfigToString() {
        const str = yaml.stringify(this.config);
        if (process.env.NODE_ENV == 'development') {
            return str;
        } else {
            const encrypted = Util.encrypt(this.secretKey, str);
            return encrypted;
        }
    }

    private deleteUserSensitiveData(user?: User) {
        delete user?.apiKey;
        delete user?.twoFASecret;
        delete user?.password;
        //delete user?.roleIds;// is this necessary
    }


    async getUserByUsername(username: string): Promise<User | undefined> {
        if (!username) return undefined;
        let user = Util.clone(this.config.users.find(x => x.username == username));
        this.deleteUserSensitiveData(user);
        return user;
    }
    async getUserByUsernameAndSource(username: string, source: string): Promise<User | undefined> {
        if (!username) return undefined;
        let user = Util.clone(this.config.users.find(x => x.username == username && x.source == source));
        this.deleteUserSensitiveData(user);
        return user;
    }
    async getUserByApiKey(key: string): Promise<User | undefined> {
        if (!key) return undefined;
        let user = Util.clone(this.config.users.find(x => x.apiKey == key));
        this.deleteUserSensitiveData(user);
        return user;
    }
    async getUserById(id: string): Promise<User | undefined> {
        let user = Util.clone(this.config.users.find(x => x.id == id));
        this.deleteUserSensitiveData(user);
        return user;
    }
    async getUser(id: string) {
        return await this.getUserById(id);
    }

    async getUsersBy(page: number = 0, pageSize: number = 0, search?: string,
        ids?: string[], groupIds?: string[], roleIds?: string[],
        is2FA?: boolean, isVerified?: boolean, isLocked?: boolean,
        isEmailVerified?: boolean, isOnlyApiKey?: boolean) {

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
            let user = Util.clone(iterator);
            this.deleteUserSensitiveData(user);
            users.push(user);
        }

        return { items: users, total: totalSize };
    }
    async getUserByRoleIds(roleIds: string[]): Promise<User[]> {
        let users = [];
        const filteredUsers = this.config.users.filter(x => Util.isArrayElementExist(roleIds, x.roleIds))
        for (const iterator of filteredUsers) {
            let user = Util.clone(iterator);
            this.deleteUserSensitiveData(user);
            users.push(user);
        }

        return users;
    }
    async deleteUser(id: string) {
        const indexId = this.config.users.findIndex(x => x.id == id);
        if (indexId >= 0) {
            this.config.users.splice(indexId, 1);

        }

        await this.saveConfigToFile();
    }

    async getUserRoles(user: User) {
        const rbac = await this.getRBAC();
        //const sensitiveData = await this.getUserSensitiveData(user.id);
        return RBACDefault.convert2RoleList(rbac, user.roleIds);
    }
    async getUserByUsernameAndPass(username: string, pass: string): Promise<User | undefined> {
        if (!username) return undefined;
        if (!username.trim()) return undefined;
        let user = this.config.users
            .find(x => x.username == username);

        if (user && Util.bcryptCompare(pass, user.password || '')) {
            let cloned = Util.clone(user);
            this.deleteUserSensitiveData(cloned);
            return cloned;
        }
        return undefined;

    }
    async getUserSensitiveData(id: string) {
        let user = Util.clone(this.config.users.find(x => x.id == id)) as User;
        return { twoFASecret: user?.twoFASecret };
    }
    async saveUser(user: User) {
        let cloned = Util.clone(user);
        let finded: User | undefined = undefined;

        finded = this.config.users.find(x => x.username == user.username);

        if (!finded) {
            this.config.users.push(cloned);
            finded = cloned;
        }
        else {
            cloned.id = finded.id;//security
            let newone = {
                ...finded,
                ...cloned
            }
            Object.assign(finded, newone)
        }
        /*  if (finded) {
             if (!finded.source) {
                 throw new Error('user source must exits');
             }
               if (finded.source != 'local') {
                  this.deleteUserSensitiveData(user);
              }

            }*/
        await this.saveConfigToFile();
    }
    async changeAdminUser(email: string, password: string) {
        let finded = this.config.users.find(x => x.username == 'admin');
        if (!finded)
            return;

        finded.username = email;
        finded.password = Util.bcryptHash(password);
        finded.updateDate = new Date().toISOString();
        await this.saveConfigToFile();
    }
    async getCaptcha(): Promise<Captcha> {
        return Util.clone(this.config.captcha);
    }
    async setCaptcha(captcha: Captcha | {}) {
        let cloned = Util.clone(captcha);
        this.config.captcha = {
            ...this.config.captcha,
            ...cloned
        }
        await this.saveConfigToFile();
    }

    async getJWTSSLCertificate(): Promise<SSLCertificate> {
        return Util.clone(this.config.jwtSSLCertificate);
    }
    async setJWTSSLCertificate(cert: SSLCertificate | {}) {
        let cloned = Util.clone(cert);
        this.config.jwtSSLCertificate = {
            ...this.config.jwtSSLCertificate,
            ...cloned
        }
        await this.saveConfigToFile();
    }
    async getSSHCertificate(): Promise<SSHCertificate> {
        return Util.clone(this.config.sshCertificate);
    }
    async setSSHCertificate(cert: SSHCertificate | {}) {
        let cloned = Util.clone(cert);
        this.config.sshCertificate = {
            ...this.config.sshCertificate,
            ...cloned
        }
        await this.saveConfigToFile();
    }


    async getEmailSettings(): Promise<EmailSettings> {
        return Util.clone(this.config.email);
    }

    async setEmailSettings(options: EmailSettings) {
        let cloned = Util.clone(options);
        this.config.email = {
            ...this.config.email,
            ...cloned
        }
        await this.saveConfigToFile();
    }

    async getLogo(): Promise<LogoSettings> {
        return Util.clone(this.config.logo);
    }
    async setLogo(logo: LogoSettings | {}) {
        let cloned = Util.clone(logo);
        this.config.logo = {
            ...this.config.logo,
            ...cloned
        }
        await this.saveConfigToFile();
    }

    async getAuthSettings(): Promise<AuthSettings> {
        return Util.clone(this.config.auth);
    }
    // needs a sync version
    getAuthSettingsSync(): AuthSettings {
        return Util.clone(this.config.auth);
    }
    async setAuthSettings(option: AuthSettings | {}) {
        let cloned = Util.clone(option);
        this.config.auth = {
            ...this.config.auth,
            ...cloned
        }
        await this.saveConfigToFile();
    }
    async setAuthSettingsCommon(common: AuthCommon) {
        let cloned = Util.clone(common);
        this.config.auth.common = cloned;
        await this.saveConfigToFile();
    }
    async getAuthSettingsCommon() {
        const common = Util.clone(this.config.auth.common);
        return common;
    }


    async setAuthSettingsLocal(local: AuthLocal) {
        let cloned = Util.clone(local);
        this.config.auth.local = cloned;
        await this.saveConfigToFile();
    }
    async getAuthSettingsLocal() {
        const common = Util.clone(this.config.auth.local);
        return common;
    }

    async getAuthSettingOAuth() {
        return Util.clone(this.config.auth.oauth || {}) as AuthOAuth
    }

    async addAuthSettingOAuth(provider: BaseOAuth) {
        let cloned = Util.clone(provider);
        if (!this.config.auth.oauth)
            this.config.auth.oauth = { providers: [] };
        const index = this.config.auth.oauth.providers.findIndex(x => x.id == cloned.id);
        if (index < 0)
            this.config.auth.oauth.providers.push(cloned);
        else
            this.config.auth.oauth.providers[index] = {
                ...cloned
            }
        await this.saveConfigToFile();
    }

    async deleteAuthSettingOAuth(id: string) {
        const index = this.config.auth?.oauth?.providers.findIndex(x => x.id == id);
        if (Number(index) >= 0)
            this.config.auth.oauth?.providers.splice(Number(index), 1);
        await this.saveConfigToFile();
    }

    async getAuthSettingLdap() {
        return Util.clone(this.config.auth.ldap || {}) as AuthLdap
    }
    async addAuthSettingLdap(provider: BaseLdap) {
        let cloned = Util.clone(provider);
        if (!this.config.auth.ldap)
            this.config.auth.ldap = { providers: [] };
        const index = this.config.auth.ldap.providers.findIndex(x => x.id == cloned.id);
        if (index < 0)
            this.config.auth.ldap.providers.push(cloned);
        else
            this.config.auth.ldap.providers[index] = {
                ...cloned
            }
        await this.saveConfigToFile();
    }
    async deleteAuthSettingLdap(id: string) {
        const index = this.config.auth?.ldap?.providers.findIndex(x => x.id == id);
        if (Number(index) >= 0)
            this.config.auth.ldap?.providers.splice(Number(index), 1);
        await this.saveConfigToFile();
    }

    async getAuthSettingSaml() {
        return Util.clone(this.config.auth.saml || {}) as AuthSaml
    }


    async addAuthSettingSaml(provider: BaseSaml) {
        let cloned = Util.clone(provider);
        if (!this.config.auth.saml)
            this.config.auth.saml = { providers: [] };
        const index = this.config.auth.saml.providers.findIndex(x => x.id == cloned.id);
        if (index < 0)
            this.config.auth.saml.providers.push(cloned);
        else
            this.config.auth.saml.providers[index] = {
                ...cloned
            }
        await this.saveConfigToFile();
    }


    async deleteAuthSettingSaml(id: string) {
        const index = this.config.auth?.saml?.providers.findIndex(x => x.id == id);
        if (Number(index) >= 0)
            this.config.auth.saml?.providers.splice(Number(index), 1);
        await this.saveConfigToFile();
    }

    async getNetwork(id: string) {
        const network = this.config.networks.find(x => x.id == id);
        if (!network) {
            return network;
        }
        return Util.clone(network);
    }

    async deleteNetwork(id: string) {
        const indexId = this.config.networks.findIndex(x => x.id == id);
        if (indexId >= 0) {
            this.config.networks.splice(indexId, 1);

        }
        this.config.gateways.forEach(x => {
            if (x.networkId == id)
                x.networkId = '';
        })
        await this.saveConfigToFile();
    }

    async getNetworkByName(name: string) {
        const network = this.config.networks.find(x => x.name == name);
        if (!network) {
            return network;
        }
        return Util.clone(network);
    }
    async getNetworkByHost(hostId: string) {
        const gateway = this.config.gateways.find(x => x.id == hostId);
        if (!gateway || !gateway.networkId) {
            return null;
        }
        const network = this.config.networks.find(x => x.id == gateway.networkId);
        if (!network) return null;
        return Util.clone(network);
    }

    async getNetworksBy(query: string) {
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
        return networks.map(x => Util.clone(x));
    }
    async getNetworksAll() {
        return this.config.networks.map(x => Util.clone(x));
    }


    async saveNetwork(network: Network) {
        let findedIndex = this.config.networks.findIndex(x => x.id == network.id);
        let finded = findedIndex >= 0 ? this.config.networks[findedIndex] : null;
        const cloned = Util.clone(network);
        if (!finded) {
            this.config.networks.push(cloned);
        } else {
            this.config.networks[findedIndex] = {
                ...finded,
                ...cloned
            }
        }
        await this.saveConfigToFile();
    }
    async getDomain(): Promise<string> {
        return this.config.domain;
    }

    async getGateway(id: string) {
        const gateway = this.config.gateways.find(x => x.id == id);
        if (!gateway) {
            return gateway;
        }
        return Util.clone(gateway);
    }

    async deleteGateway(id: string) {
        const indexId = this.config.gateways.findIndex(x => x.id == id);
        if (indexId >= 0) {
            this.config.gateways.splice(indexId, 1);

        }
        await this.saveConfigToFile();
    }
    async getGatewaysByNetworkId(id: string) {
        if (id) {
            const gateways = this.config.gateways.filter(x => x.networkId == id);
            return gateways.map(x => Util.clone(x));
        } else {
            const gateways = this.config.gateways.filter(x => !x.networkId);
            return gateways.map(x => Util.clone(x));
        }
    }
    async getGatewaysBy(query: string) {
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
        return this.config.gateways.map(x => Util.clone(x));
    }

    async saveGateway(gateway: Gateway) {
        let findedIndex = this.config.gateways.findIndex(x => x.id == gateway.id);
        let finded = findedIndex >= 0 ? this.config.gateways[findedIndex] : null;
        const cloned = Util.clone(gateway);
        if (!finded) {
            this.config.gateways.push(cloned);
        } else {
            this.config.gateways[findedIndex] = {
                ...finded,
                ...cloned
            }
        }
        await this.saveConfigToFile();
    }

    async setDomain(domain: string) {
        this.config.domain = domain;
        await this.saveConfigToFile();
    }


    async getUrl(): Promise<string> {
        return this.config.url;
    }
    async setUrl(url: string) {
        this.config.url = url;
        await this.saveConfigToFile();
    }

    async getRBAC(): Promise<RBAC> {
        return Util.clone(this.config.rbac);
    }

    async getIsConfigured(): Promise<number> {
        return this.config.isConfigured;
    }

    async setIsConfigured(val: number) {
        this.config.isConfigured = val;
        await this.saveConfigToFile();
    }

    //// group entity
    async getGroup(id: string): Promise<Group | undefined> {
        return Util.clone(this.config.groups.find(x => x.id == id));

    }

    async getGroupsBySearch(query: string) {
        const search = query.toLowerCase();
        const groups = this.config.groups.filter(x => {
            if (x.labels?.length && x.labels.find(y => y.toLowerCase().includes(search)))
                return true;
            if (x.name?.toLowerCase().includes(search))
                return true;

            return false;
        });
        return groups.map(x => Util.clone(x));
    }
    async getGroupsAll() {
        return this.config.groups.map(x => Util.clone(x));
    }

    async deleteGroup(id: string) {
        const indexId = this.config.groups.findIndex(x => x.id == id);
        if (indexId >= 0) {
            this.config.groups.splice(indexId, 1);

        }
        this.config.users.forEach(x => {
            let userGroupIndex = x.groupIds.findIndex(y => y == id)
            if (userGroupIndex >= 0)
                x.groupIds.splice(userGroupIndex, 1);

        })
        await this.saveConfigToFile();
    }

    async saveGroup(group: Group) {
        let findedIndex = this.config.groups.findIndex(x => x.id == group.id);
        let finded = findedIndex >= 0 ? this.config.groups[findedIndex] : null;
        const cloned = Util.clone(group);
        if (!finded) {
            this.config.groups.push(cloned);
        } else {
            this.config.groups[findedIndex] = {
                ...finded,
                ...cloned
            }
        }
        await this.saveConfigToFile();
    }


    //// service entity
    async getService(id: string): Promise<Service | undefined> {

        return Util.clone(this.config.services.find(x => x.id == id));

    }

    async getServicesBy(query?: string, networkIds?: string[], ids?: string[]) {
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
        return services.map(x => Util.clone(x));
    }

    async getServicesByNetworkId(networkId: string) {
        return this.config.services.filter(x => x.networkId == networkId).map(x => Util.clone(x));
    }

    //// service entity
    async getServicesAll(): Promise<Service[]> {

        return this.config.services.map(x => Util.clone(x));

    }



    async deleteService(id: string) {
        const indexId = this.config.services.findIndex(x => x.id == id);
        if (indexId >= 0) {
            this.config.services.splice(indexId, 1);
        }

        await this.saveConfigToFile();
    }

    async saveService(service: Service) {
        let findedIndex = this.config.services.findIndex(x => x.id == service.id);
        let finded = findedIndex >= 0 ? this.config.services[findedIndex] : null;
        const cloned = Util.clone(service);
        if (!finded) {

            this.config.services.push(cloned);
        } else {
            this.config.services[findedIndex] = {
                ...finded,
                ...cloned
            }
        }
        await this.saveConfigToFile();
    }




}
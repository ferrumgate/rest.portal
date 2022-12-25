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
import { isAbsolute } from "path";
import { Group } from "../model/group";
import { util } from "chai";
import { Service } from "../model/service";
import { AuthenticationRule } from "../model/authenticationPolicy";
import { AuthorizationRule } from "../model/authorizationPolicy";
import { urlToHttpOptions } from "url";
import { EventEmitter } from "stream";
import { runInThisContext } from "vm";



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
            email: {
                type: 'empty',
                fromname: '', pass: '', user: ''
            },
            logo: {},
            auth: {
                common: {},
                local: {
                    id: Util.randomNumberString(16),
                    type: 'local',
                    baseType: 'local',
                    name: 'Local',
                    tags: [],
                    isForgotPassword: false,
                    isRegister: false,
                    isEnabled: true,
                    insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()

                },
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
                rules: [
                ],
            },
            authorizationPolicy: { rules: [] }


        }
        // start point for delete
        //for testing start
        //dont delete aboveline
        if (process.env.NODE_ENV == 'development') {
            this.config.auth.oauth = {
                providers: [
                    {
                        baseType: 'oauth',
                        type: 'google',
                        id: Util.randomNumberString(16),
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
                        id: Util.randomNumberString(16),
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
                        id: Util.randomNumberString(16),
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
                        id: Util.randomNumberString(16),
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

            const reporterUser = HelperService.createUser('local-local', 'hamzareporter@hamzakilic.com', 'hamzareporter', 'Deneme123');
            reporterUser.isLocked = false;
            reporterUser.isVerified = true;
            reporterUser.roleIds = ['Reporter'];
            this.config.users.push(reporterUser);

            this.config.groups.push({
                id: Util.randomNumberString(16),
                name: 'north',
                isEnabled: true, insertDate: new Date().toISOString(), updateDate: new Date().toISOString(), labels: []
            })
            this.config.groups.push({
                id: Util.randomNumberString(16),
                name: 'south',
                isEnabled: true, insertDate: new Date().toISOString(), updateDate: new Date().toISOString(), labels: []
            })
            // some networks
            let net: Network = {

                id: Util.randomNumberString(16), name: 'ops', labels: ['deneme2'],
                serviceNetwork: '1.1.1.1/16',
                clientNetwork: '1.2.3.4/24',
                insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString()
            }
            this.config.networks.push(net);


            let gateways: Gateway[] = [
                {
                    id: '123', networkId: net.id, name: 'blac1', labels: ['testme'], isEnabled: true, insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()
                },
                {
                    id: '1234', networkId: net.id, name: 'blac2', labels: ['testme2'], isEnabled: true, insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()
                },
                {
                    id: '12345', networkId: net.id, name: 'blac3', labels: ['testme3', 'testme2'], isEnabled: false, insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()
                },
                {
                    id: '123456', networkId: '', name: 'blac4', labels: ['testme3'], isEnabled: false, insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()
                },
                {
                    id: '1234567', networkId: '', name: 'blac5', labels: ['testme5'], isEnabled: false, insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()
                }
            ];
            gateways.forEach(x => this.config.gateways.push(x));
            const service1 = {
                id: Util.randomNumberString(16),
                name: 'mysql-dev', host: '10.0.0.12', protocol: 'raw', tcp: 3306,
                assignedIp: '10.3.4.4', isEnabled: true, networkId: net.id, labels: [],
                insertDate: new Date().toISOString(), updateDate: new Date().toISOString(), isSystem: true, count: 1
            }
            this.config.services.push(service1);

            const service2 = {
                id: Util.randomNumberString(16),
                name: 'ssh-dev', host: '10.0.0.12', protocol: 'raw', tcp: 22,
                assignedIp: '10.3.4.4', isEnabled: true, networkId: net.id, labels: [],
                insertDate: new Date().toISOString(), updateDate: new Date().toISOString(), count: 1
            }

            this.config.services.push(service2);

            const service3 = {
                id: Util.randomNumberString(16),
                name: 'mysql-prod', host: '10.0.0.12', protocol: 'raw', tcp: 22,
                assignedIp: '10.3.4.4', isEnabled: true, networkId: defaultNetwork.id, labels: [], count: 1,
                insertDate: new Date().toISOString(), updateDate: new Date().toISOString()
            }
            this.config.services.push(service3);


            //authiraziton policy
            this.config.authorizationPolicy.rules.push({
                id: Util.randomNumberString(16),
                name: 'tst1',
                isEnabled: true,
                networkId: net.id,
                serviceId: service1.id,
                userOrgroupIds: [standartUser.id],
                profile: { is2FA: false },
                updateDate: new Date().toISOString(),
                insertDate: new Date().toISOString()
            })

            //
            this.config.authenticationPolicy.rules.push({

                id: Util.randomNumberString(16),
                name: 'abc rule',
                networkId: net.id,
                userOrgroupIds: [standartUser.id],
                action: 'allow',
                profile: { is2FA: true },
                isEnabled: true,
                updateDate: new Date().toISOString(),
                insertDate: new Date().toISOString()

            })

            this.config.authenticationPolicy.rules.push({

                id: Util.randomNumberString(16),
                name: 'abc2',
                networkId: net.id,
                userOrgroupIds: [adminUser.id],
                action: 'deny',
                profile: { is2FA: true },
                isEnabled: true,
                updateDate: new Date().toISOString(),
                insertDate: new Date().toISOString()

            })
            this.config.authenticationPolicy.rules.push({

                id: Util.randomNumberString(16),
                name: 'def2',
                networkId: net.id,
                userOrgroupIds: [adminUser.id],
                action: 'deny',
                profile: { is2FA: true },
                isEnabled: true,
                updateDate: new Date().toISOString(),
                insertDate: new Date().toISOString()

            })

        }
        this.config.lastUpdateTime = new Date().toISOString();

        //dont delete below line
        //for testing end
        // end point for delete
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
        return this.config.lastUpdateTime;
    }
    async saveLastUpdateTime() {
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
        return event;
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
    async getUserCount() {
        return this.config.users.length;
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
    async getUserByIdAndPass(id: string, pass: string): Promise<User | undefined> {
        if (!id) return undefined;
        if (!id.trim()) return undefined;
        let user = this.config.users
            .find(x => x.id == id);

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

    async triggerUserDeleted(user: User) {
        //check policy authentication

        let rulesAuthnChanged: { previous: AuthenticationRule, item: AuthenticationRule }[] = [];
        this.config.authenticationPolicy.rules.forEach(x => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == user.id);
            if (userIdIndex >= 0) {
                const prev = Util.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);
                rulesAuthnChanged.push({ previous: prev, item: x });
            }
        })
        //check authorization

        let rulesAuthzChanged: { previous: AuthorizationRule, item: AuthorizationRule }[] = [];
        this.config.authorizationPolicy.rules.forEach(x => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == user.id);
            if (userIdIndex >= 0) {
                const prev = Util.clone(x);
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
        let cloned = Util.clone(user);

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
        let finded = this.config.users.find(x => x.username == 'admin');
        if (!finded)
            return;
        const prev = Util.clone(finded);
        finded.username = email;
        finded.name = email;
        finded.password = Util.bcryptHash(password);
        finded.updateDate = new Date().toISOString();
        this.emitEvent({ type: 'updated', path: '/users', data: this.createTrackEvent(prev, finded) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, finded);
    }
    async getCaptcha(): Promise<Captcha> {
        return Util.clone(this.config.captcha);
    }

    async setCaptcha(captcha: Captcha | {}) {
        let cloned = Util.clone(captcha);
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
        return Util.clone(this.config.jwtSSLCertificate);
    }

    async setJWTSSLCertificate(cert: SSLCertificate | {}) {
        let cloned = Util.clone(cert);
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
        return Util.clone(this.config.sslCertificate);
    }

    async setSSLCertificate(cert: SSLCertificate | {}) {
        let cloned = Util.clone(cert);
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
        return Util.clone(this.config.caSSLCertificate);
    }
    async getCASSLCertificatePublic(): Promise<string | null | undefined> {
        return this.config.caSSLCertificate.publicKey;
    }

    async setCASSLCertificate(cert: SSLCertificate | {}) {
        let cloned = Util.clone(cert);
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
        return Util.clone(this.config.email);
    }

    async setEmailSettings(options: EmailSettings) {
        let cloned = Util.clone(options);
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
        return Util.clone(this.config.logo);
    }
    async setLogo(logo: LogoSettings | {}) {
        let cloned = Util.clone(logo);
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
        return Util.clone(this.config.auth);
    }
    // needs a sync version
    getAuthSettingsSync(): AuthSettings {
        return Util.clone(this.config.auth);
    }
    async setAuthSettings(option: AuthSettings | {}) {
        let cloned = Util.clone(option);
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
        let cloned = Util.clone(common);
        let prev = this.config.auth.common;
        this.config.auth.common = cloned;
        this.emitEvent({ type: 'updated', path: '/auth/common', data: this.createTrackEvent(prev, this.config.auth.common) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.auth.common);
    }
    async getAuthSettingsCommon() {
        const common = Util.clone(this.config.auth.common);
        return common;
    }


    async setAuthSettingsLocal(local: AuthLocal) {
        let cloned = Util.clone(local);
        const prev = this.config.auth.local;
        this.config.auth.local = cloned;
        this.emitEvent({ type: 'updated', path: '/auth/local', data: this.createTrackEvent(prev, this.config.auth.local) })
        await this.saveConfigToFile();
        return this.createTrackEvent(prev, this.config.auth.local);
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
        return Util.clone(this.config.auth.ldap || {}) as AuthLdap
    }
    async addAuthSettingLdap(provider: BaseLdap) {
        let cloned = Util.clone(provider);
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
        return Util.clone(this.config.auth.saml || {}) as AuthSaml
    }


    async addAuthSettingSaml(provider: BaseSaml) {
        let cloned = Util.clone(provider);
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
        const network = this.config.networks.find(x => x.id == id);
        if (!network) {
            return network;
        }
        return Util.clone(network);
    }
    async getNetworkCount() {
        return this.config.networks.length;
    }

    async triggerNetworkDeleted(net: Network) {
        ////// gateways
        let changedGateways = this.config.gateways.filter(x => x.networkId == net.id);
        changedGateways.forEach(x => {
            let previous = Util.clone(x);
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
        const network = this.config.networks.find(x => x.name == name);
        if (!network) {
            return network;
        }
        return Util.clone(network);
    }
    async getNetworkByGateway(gatewayId: string) {
        const gateway = this.config.gateways.find(x => x.id == gatewayId);
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
        let finded = this.config.networks[findedIndex];
        const cloned = Util.clone(network);
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
        return this.config.domain;
    }

    async getGateway(id: string) {
        const gateway = this.config.gateways.find(x => x.id == id);
        if (!gateway) {
            return gateway;
        }
        return Util.clone(gateway);
    }
    async getGatewayCount() {
        return this.config.gateways.length;
    }
    async triggerGatewayDeleted(gate: Gateway) {
        this.emitEvent({ type: 'deleted', path: '/gateways', data: this.createTrackEvent(gate) });
    }

    async deleteGateway(id: string) {
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

    async setDomain(domain: string) {
        let previous = this.config.domain;
        this.config.domain = domain;
        this.emitEvent({ type: 'updated', path: '/domain', data: this.createTrackEvent(previous, this.config.domain) })
        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.domain);
    }


    async getUrl(): Promise<string> {
        return this.config.url;
    }
    async setUrl(url: string) {
        let previous = this.config.url;
        this.config.url = url;
        this.emitEvent({ type: 'updated', path: '/url', data: this.createTrackEvent(previous, this.config.url) })
        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.url);
    }

    async getRBAC(): Promise<RBAC> {
        return Util.clone(this.config.rbac);
    }

    async getIsConfigured(): Promise<number> {
        return this.config.isConfigured;
    }

    async setIsConfigured(val: number) {
        let previous = this.config.isConfigured;
        this.config.isConfigured = val;
        this.emitEvent({ type: 'updated', path: '/isConfigured', data: this.createTrackEvent(previous, this.config.isConfigured) })
        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.isConfigured);
    }

    //// group entity
    async getGroup(id: string): Promise<Group | undefined> {
        return Util.clone(this.config.groups.find(x => x.id == id));

    }
    async getGroupCount() {
        return this.config.groups.length;
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

    async triggerDeleteGroup(grp: Group) {

        let usersChanged: { previous: User, item: User }[] = [];
        this.config.users.forEach(x => {
            let userGroupIndex = x.groupIds.findIndex(y => y == grp.id)
            if (userGroupIndex >= 0) {
                let cloned = Util.clone(x);
                x.groupIds.splice(userGroupIndex, 1);
                usersChanged.push({ previous: cloned, item: x })
            }
        })

        //check policy authentication

        let rulesAuthnChanged: { previous: AuthenticationRule, item: AuthenticationRule }[] = [];
        this.config.authenticationPolicy.rules.forEach(x => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == grp.id);
            if (userIdIndex >= 0) {
                let cloned = Util.clone(x);
                x.userOrgroupIds.splice(userIdIndex, 1);

                rulesAuthnChanged.push({ previous: cloned, item: x });
            }
        })
        //check authorization

        let rulesAuthzChanged: { previous: AuthorizationRule, item: AuthorizationRule }[] = [];
        this.config.authorizationPolicy.rules.forEach(x => {
            const userIdIndex = x.userOrgroupIds.findIndex(x => x == grp.id);
            if (userIdIndex >= 0) {
                let cloned = Util.clone(x);
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
        let findedIndex = this.config.groups.findIndex(x => x.id == group.id);
        let finded = findedIndex >= 0 ? this.config.groups[findedIndex] : null;
        const cloned = Util.clone(group);
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

        return Util.clone(this.config.services.find(x => x.id == id));

    }
    async getServiceCount() {
        return this.config.services.length;
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

    /**
     * @summary create tracking items
     * @param previous 
     * @param item 
     * @returns 
     */
    createTrackEvent(previous?: any, item?: any) {
        return {
            before: Util.isUndefinedOrNull(previous) ? undefined : Util.clone(previous),
            after: Util.isUndefinedOrNull(item) ? undefined : Util.clone(item)

        }
    }
    /**
     * @summary tracks an array object, if something changes
     */
    createTrackIndexEvent(item: any, iprevious: number, iitem: number) {
        return {
            item: Util.clone(item),
            iBefore: iprevious,
            iAfter: iitem
        }
    }

    async triggerServiceDeleted(svc: Service) {

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
        let findedIndex = this.config.services.findIndex(x => x.id == service.id);
        let finded = findedIndex >= 0 ? this.config.services[findedIndex] : null;
        const cloned = Util.clone(service);
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
        const cloned = Util.clone(arule);
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
            ruleIndex = this.config.authenticationPolicy.rules.length - 1;
            this.emitEvent({ type: 'saved', path: '/authenticationPolicy/rules', data: this.createTrackEvent(previous, this.config.authenticationPolicy.rules[ruleIndex]) })
        }

        this.emitEvent({ type: 'updated', path: '/authenticationPolicy' })
        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.authenticationPolicy.rules[ruleIndex])
    }
    async getAuthenticationPolicy() {
        return Util.clone(this.config.authenticationPolicy);
    }

    async getAuthenticationPolicyUnsafe() {
        return this.config.authenticationPolicy;
    }
    async getAuthenticationPolicyRule(id: string) {
        const rule = this.config.authenticationPolicy.rules.find(x => x.id == id);
        return Util.clone(rule);
    }
    async getAuthenticationPolicyRuleCount() {
        return this.config.authenticationPolicy.rules.length;
    }

    async deleteAuthenticationPolicyRule(id: string) {
        const ruleIndex = this.config.authenticationPolicy.rules.findIndex(x => x.id == id);
        const rule = this.config.authenticationPolicy.rules.find(x => x.id == id);
        if (ruleIndex >= 0 && rule) {
            this.config.authenticationPolicy.rules.splice(ruleIndex, 1);
            this.emitEvent({ type: 'deleted', path: '/authenticationPolicy/rules', data: this.createTrackEvent(rule) })
            this.emitEvent({ type: 'updated', path: '/authenticationPolicy' })
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(rule);
    }
    /* async updateAuthenticationPolicyUpdateTime() {
        this.config.authenticationPolicy.updateDate = new Date().toISOString();
        await this.saveConfigToFile();
    } */
    async updateAuthenticationRulePos(id: string, previous: number, index: number) {
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
        const cloned = Util.clone(arule);
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
            ruleIndex = this.config.authenticationPolicy.rules.length - 1;
            this.emitEvent({ type: 'saved', path: '/authorizationPolicy/rules', data: this.createTrackEvent(previous, this.config.authorizationPolicy.rules[ruleIndex]) })
        }

        this.emitEvent({ type: 'updated', path: '/authorizationPolicy' })
        await this.saveConfigToFile();
        return this.createTrackEvent(previous, this.config.authorizationPolicy.rules[ruleIndex]);

    }
    async getAuthorizationPolicy() {
        return Util.clone(this.config.authorizationPolicy);
    }
    async getAuthorizationPolicyUnsafe() {
        return this.config.authorizationPolicy;
    }
    async getAuthorizationPolicyRule(id: string) {
        const rule = this.config.authorizationPolicy.rules.find(x => x.id == id);
        return Util.clone(rule);
    }

    async getAuthorizationPolicyRuleCount() {
        return this.config.authorizationPolicy.rules.length;
    }
    async deleteAuthorizationPolicyRule(id: string) {
        const ruleIndex = this.config.authorizationPolicy.rules.findIndex(x => x.id == id);
        const rule = this.config.authorizationPolicy.rules.find(x => x.id == id);
        if (ruleIndex >= 0 && rule) {
            this.config.authorizationPolicy.rules.splice(ruleIndex, 1);
            this.emitEvent({ type: 'deleted', path: '/authorizationPolicy/rules', data: this.createTrackEvent(rule) })
            this.emitEvent({ type: 'updated', path: '/authorizationPolicy' })
            await this.saveConfigToFile();
        }
        return this.createTrackEvent(rule);
    }





}
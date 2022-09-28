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
import { AuthSettings } from "../model/authSettings";
import { RBAC, RBACDefault, Role } from "../model/rbac";
import { HelperService } from "./helperService";
import { Gateway, Network } from "../model/network";



export class ConfigService {


    config: Config;
    protected configfile = '/etc/ferrumgate/config.yaml';
    private secretKey = '';
    lastUpdateTime = '';
    /**
     *
     */
    constructor(encryptKey: string, configFile?: string) {
        if (!encryptKey)
            throw new Error('needs and encyption key with lenght 32');
        //default user
        const adminUser = HelperService.createUser('default', 'admin', 'default admin', 'ferrumgate');
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
            captcha: {},
            sshCertificate: {},
            jwtSSLCertificate: {},
            domain: 'ferrumgate.local',
            url: 'https://secure.yourdomain.com',
            email: {
                type: 'unknown',
                fromname: '', pass: '', user: ''
            },
            logo: {},
            auth: {
                local: { isForgotPassword: 0, isRegister: 0 }
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
            this.config.auth.google = {
                clientID: '920409807691-jp82nth4a4ih9gv2cbnot79tfddecmdq.apps.googleusercontent.com',
                clientSecret: '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',
            }
            this.config.auth.linkedin = {
                clientID: '866dr29tuc5uy5',
                clientSecret: '1E3DHw0FJFUsp1Um'
            }
            this.config.email = { fromname: 'ferrumgate', type: 'google', user: 'ferrumgates@gmail.com', pass: '}Q]@c836}7$F+AwK' };
            this.config.url = 'http://localhost:4200';
            this.config.captcha = {
                client: '6Lcw_scfAAAAABL_DeZVQNd-yNHp0CnNYE55rifH',
                server: '6Lcw_scfAAAAAFKwZuGa9vxuFF7ezh8ZtsQazdS0'
            }

            this.config.jwtSSLCertificate.privateKey = fs.readFileSync(`./ferrumgate.com.key`).toString();
            this.config.jwtSSLCertificate.publicKey = fs.readFileSync(`./ferrumgate.com.crt`).toString();
            if (fs.existsSync('/tmp/config.yaml') && !process.env.LOCAL_TEST)
                fs.rmSync('/tmp/config.yaml');
            const adminUser = HelperService.createUser('local', 'hamza@hamzakilic.com', 'hamzaadmin', 'Deneme123');
            adminUser.isLocked = false;
            adminUser.isVerified = true;
            adminUser.roleIds = ['Admin'];
            adminUser.is2FA = true;
            adminUser.twoFASecret = 'GZTM2CLFZFQA4W3QSCOGG53QKU23CAZW';
            this.config.users.push(adminUser);

            const standartUser = HelperService.createUser('local', 'hamzauser@hamzakilic.com', 'hamzauser', 'Deneme123');
            standartUser.isLocked = false;
            standartUser.isVerified = true;
            standartUser.roleIds = ['User'];
            this.config.users.push(standartUser);

        }
        this.loadConfigFromFile();

        this.lastUpdateTime = new Date().toISOString();
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
        delete user?.roleIds;
    }

    async getUserByUsername(username: string): Promise<User | undefined> {
        if (!username) return undefined;
        let user = Util.clone(this.config.users.find(x => x.username == username));
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

    async getUserRoles(user: User) {
        const rbac = await this.getRBAC();
        const sensitiveData = await this.getUserSensitiveData(user.id);
        return RBACDefault.convert2RoleList(rbac, sensitiveData.roleIds);
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
        return { twoFASecret: user?.twoFASecret, roleIds: user.roleIds };
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

    async setEmailSettings(options: EmailSettings | {}) {
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

    async getNetworksBySearch(query: string) {
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
    async getGatewaysBySearch(query: string) {
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


    /**
     * @summary save or update role
     * @param role 
     * @remark this is implemented but not used, because we dont need it I think
     * lets think more about this functionality
     * I did not implement a test code for this
     */
    /*  async setRBAC(role: Role) {
         const cloned = Util.clone(role) as Role;
         //security check, one one can add default admin rights to any role
         if (RBACDefault.systemRoleIds.includes(cloned.id)) {
             logger.error(`no one can use default role id: ${cloned.id}`);
             throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'role id problem')
         }
         if (RBACDefault.systemRightIds.find(x => cloned.rightIds?.includes(x))) {
             logger.error(`no one can use default right id: ${cloned.id}`);
             throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'right id problem')
         }
         if (cloned.rightIds) {
             //only defined right ids
             cloned.rightIds = cloned.rightIds.filter(x => RBACDefault.rightIds.includes(x));
         }
         const finded = this.config.rbac.roles.find(x => x.id == cloned.id);
         if (finded) {
             finded.name = cloned.name;
             finded.rightIds = cloned.rightIds;
         } else
             this.config.rbac.roles.push(role);
         await this.saveConfigToFile();
 
     } */
}
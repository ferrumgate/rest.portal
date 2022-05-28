import fs from "fs";
import { logger } from "../common";
import { Config } from "../model/config";
import yaml from 'yaml';
import { Util } from "../util";
import { User } from "../model/user";
import { EmailOption } from "../model/emailOption";
import { LogoOption } from "../model/logoOption";
import { Captcha } from "../model/captcha";
import { SSLCertificate } from "../model/sslCertificate";
import { SSHCertificate } from "../model/sshCertificate";
import { ErrorCodes, RestfullException } from "../restfullException";
import { AuthOption } from "../model/authOption";
import { RBAC, RBACDefault, Role } from "../model/rbac";
import { HelperService } from "./helperService";



export class ConfigService {


    config: Config;
    protected configfile = '/etc/rest.portal/config.yaml';
    private secretKey = '';
    lastUpdateTime = '';
    /**
     *
     */
    constructor(encryptKey: string, configFile?: string) {
        if (!encryptKey)
            throw new Error('needs and encyption key with lenght 32');
        this.secretKey = encryptKey;
        if (configFile)
            this.configfile = configFile;
        this.config = {
            users: [
                HelperService.createUser('default', '', 'default admin', 'admin', 'ferrumgate'),

            ],
            captcha: {},
            sshCertificate: {},
            sslCertificate: {},
            domain: 'ferrumgate.com',
            url: 'https://portal.ferrumgate.com',
            email: {
                type: 'unknown',
                fromname: '', pass: '', user: ''
            },
            logo: {},
            auth: {},
            rbac: {
                roles: [RBACDefault.roleAdmin, RBACDefault.roleReporter, RBACDefault.roleUser],
                rights: [RBACDefault.rightAdmin, RBACDefault.rightReporter, RBACDefault.rightUser]
            }

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
            this.config.url = 'http://local.ferrumgate.com:8080';
            this.config.captcha = {
                client: '6Lcw_scfAAAAABL_DeZVQNd-yNHp0CnNYE55rifH',
                server: '6Lcw_scfAAAAAFKwZuGa9vxuFF7ezh8ZtsQazdS0'
            }
            this.config.sslCertificate.privateKey = fs.readFileSync(`./ferrumgate.com.key`).toString();
            this.config.sslCertificate.publicKey = fs.readFileSync(`./ferrumgate.com.crt`).toString();
            if (fs.existsSync('/tmp/config.yaml') && !process.env.LOCAL_TEST)
                fs.rmSync('/tmp/config.yaml');
            const adminUser = HelperService.createUser('local', 'hamza@hamzakilic.com', 'hamzaadmin', '', 'Deneme123');
            adminUser.isLocked = false;
            adminUser.isVerified = true;
            adminUser.roleIds = ['Admin'];
            this.config.users.push(adminUser);

            const standartUser = HelperService.createUser('local', 'hamzauser@hamzakilic.com', 'hamzauser', '', 'Deneme123');
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
    async getUserByEmail(email: string): Promise<User | undefined> {
        if (!email) return undefined;
        let user = Util.clone(this.config.users.find(x => x.email == email));
        this.deleteUserSensitiveData(user);
        return user;
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
    async getUserByEmailAndPass(email: string, pass: string): Promise<User | undefined> {
        if (!email) return undefined;
        if (!email.trim()) return undefined;
        let user = this.config.users
            .find(x => x.email == email);

        if (user && Util.bcryptCompare(pass, user.password || '')) {
            let cloned = Util.clone(user);
            this.deleteUserSensitiveData(cloned);
            return cloned;
        }
        return undefined;

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
        //security bariers
        if (!user.email && !user.username)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'user must have username or email');
        //security bariers
        if (user.email && user.username)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'user cannot have username and email at same time');
        if (user.email)
            finded = this.config.users.find(x => x.email == user.email);
        if (user.username)
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

    async getSSLCertificate(): Promise<SSLCertificate> {
        return Util.clone(this.config.sslCertificate);
    }
    async setSSLCertificate(cert: SSLCertificate | {}) {
        let cloned = Util.clone(cert);
        this.config.sslCertificate = {
            ...this.config.sslCertificate,
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


    async getEmailOptions(): Promise<EmailOption> {
        return Util.clone(this.config.email);
    }

    async setEmailOptions(options: EmailOption | {}) {
        let cloned = Util.clone(options);
        this.config.email = {
            ...this.config.email,
            ...cloned
        }
        await this.saveConfigToFile();
    }

    async getLogo(): Promise<LogoOption> {
        return Util.clone(this.config.logo);
    }
    async setLogo(logo: LogoOption | {}) {
        let cloned = Util.clone(logo);
        this.config.logo = {
            ...this.config.logo,
            ...cloned
        }
        await this.saveConfigToFile();
    }

    async getAuthOption(): Promise<AuthOption> {
        return Util.clone(this.config.auth);
    }
    // needs a sync version
    getAuthOptionSync(): AuthOption {
        return Util.clone(this.config.auth);
    }
    async setAuthOption(option: AuthOption | {}) {
        let cloned = Util.clone(option);
        this.config.auth = {
            ...this.config.auth,
            ...cloned
        }
        await this.saveConfigToFile();
    }
    async getDomain(): Promise<string> {
        return this.config.domain;
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
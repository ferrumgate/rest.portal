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
            users: [],
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
            if (fs.existsSync('/tmp/config.yaml') && !process.env.LOCAL_TEST)
                fs.rmSync('/tmp/config.yaml');
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
    private static clone(x: any) {

    }
    async getUserByEmail(email: string): Promise<User | undefined> {
        let user = Util.clone(this.config.users.find(x => x.email == email));
        delete user?.password;
        return user;
    }
    async getUserById(id: string): Promise<User | undefined> {
        let user = Util.clone(this.config.users.find(x => x.id == id));
        delete user?.password;
        return user;
    }
    async getUserByEmailAndPass(email: string, pass: string): Promise<User | undefined> {
        let user = this.config.users
            .find(x => x.source == 'local' && x.email == email);

        if (user && Util.bcryptCompare(pass, user.password || '')) {
            delete user.password;
            return Util.clone(user);
        }
        return undefined;

    }
    async saveUser(user: User) {
        let cloned = Util.clone(user);
        let finded = this.config.users.find(x => x.email == user.email);
        if (!finded) {
            this.config.users.push(cloned);
            finded = cloned;
        }
        else {
            user.id = finded.id;//security
            finded = {
                ...finded,
                ...cloned
            }
        }
        if (finded) {
            if (!finded.source) {
                throw new Error('user source must exits');
            }
            if (finded.source != 'local') {
                delete finded.password;
            }

        }
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
}
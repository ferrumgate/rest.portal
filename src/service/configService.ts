import fs from "fs";
import { logger } from "../common";
import { Config } from "../model/config";
import yaml from 'yaml';
import { Util } from "../util";
import { User } from "../model/user";
import { EmailOption } from "../model/emailOption";
import { LogoOption } from "../model/logoOption";

export class ConfigService {


    config: Config;
    protected configfile = '/etc/rest.portal/config.yaml';
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
        this.config = {
            users: [],
            captcha: {},
            sshCertificates: {},
            certificates: {},
            domain: 'ferrumgate.com',
            email: {
                type: 'unknown',
                fromname: '', pass: '', user: ''
            },
            logo: {}
        }
        this.loadConfigFromFile();
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
            const decrpted = Util.decrypt(this.secretKey, content);
            this.config = yaml.parse(decrpted);
        }
        this.saveAssets();
    }
    saveConfigToFile() {
        const str = yaml.stringify(this.config);
        const encrypted = Util.encrypt(this.secretKey, str);
        fs.writeFileSync(this.configfile, encrypted, { encoding: 'utf-8' });
    }
    saveConfigToString() {
        const str = yaml.stringify(this.config);
        const encrypted = Util.encrypt(this.secretKey, str);
        return encrypted;
    }
    async getUserByEmail(email: string): Promise<User | undefined> {
        return this.config.users.find(x => x.email == email);
    }
    async getUserById(id: string): Promise<User | undefined> {
        return this.config.users.find(x => x.id == id);
    }
    async saveUser(user: User) {
        let finded = this.config.users.find(x => x.email == user.email);
        if (!finded)
            this.config.users.push(user);
        else {
            user.id = finded.id;//security
            finded = {
                ...finded,
                ...user
            }
        }
        await this.saveConfigToFile();
    }
    async getCaptchaServerKey(): Promise<string | undefined> {
        return this.config.captcha?.serverKey;
    }
    async setCaptchaServerKey(key: string) {
        this.config.captcha.serverKey = key;
        await this.saveConfigToFile();
    }
    async getCaptchaClientKey(): Promise<string | undefined> {
        return this.config.captcha.clientKey;
    }
    async setCaptchaClientKey(key: string) {
        this.config.captcha.clientKey = key;
        await this.saveConfigToFile();
    }

    async getEmailOptions(): Promise<EmailOption> {
        return this.config.email;
    }

    async setEmailOptions(options: EmailOption | {}) {
        this.config.email = {
            ...this.config.email,
            ...options
        }
        await this.saveConfigToFile();
    }

    async getLogo(): Promise<LogoOption> {
        return this.config.logo;
    }
    async setLogo(logo: LogoOption | {}) {
        this.config.logo = {
            ...this.config.logo,
            ...logo
        }
        await this.saveConfigToFile();
    }
}
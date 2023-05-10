import { stdout } from "process";
import { LetsEncrypt, LetsEncryptChallenge } from "../model/letsEncrypt";
import childprocess from "child_process";
import { EventEmitter } from "node:events";
import fsp from 'fs/promises';
import { logger } from "../common";
import path from 'path';
import { ConfigService } from "./configService";
import { ConfigWatch } from "../model/config";
import { SystemLogService } from "./systemLogService";
import { Util } from "../util";
import fs from 'fs';
import { RedLockService } from "./redLockService";
import { RedisService } from "./redisService";


const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');


export class LetsEncryptService {

    /**
     *
     */
    redLock: RedLockService;
    jobList: any[] = [];
    timer: any;
    constructor(protected configService: ConfigService, protected redisService: RedisService, protected systemLogService: SystemLogService, protected challengeFolder: string) {

        this.redLock = new RedLockService(this.redisService)
    }

    async reconfigure() {
        /*  try {
             //clear job list and create new one
             if (this.timer)
                 clearIntervalAsync(this.timer);
             this.timer = null;
             this.jobList = [];
 
             const web = await this.configService.getWebSSLCertificate();
             const url = await this.configService.getUrl();
             const domain = new URL(url).hostname;
             if (web.letsEncrypt?.isEnabled) {
                 this.jobList.push({
                     isWebCert: true,
                     nextCheck: 0
                 });
             }
             await this.checkAll();
             await this.schedule();
         } catch (err) {
             logger.error(err);
         } */

    }

    /*  async checkAll() {
         logger.info('checking lets encrypt jobs');
         try {
             for (const iterator of this.jobList) {
 
             }
 
         } catch (err) {
 
         }
     }
     async schedule() {
 
     } */

    async saveChallenge(challenge: LetsEncryptChallenge) {
        await fsp.writeFile(path.join(this.challengeFolder, challenge.key), challenge.value);

    }
    async execute(data: ConfigWatch<any>) {
        try {
            logger.info(`lets encrypt execute message ${data.path}`)
            if (data.path == '/system/letsencrypt/acmechallenge') {
                logger.info(`lets encrypt saved challenge`)
                const challenge: LetsEncryptChallenge = data.val as LetsEncryptChallenge;
                await this.saveChallenge(challenge);
            }
        } catch (err) {
            logger.error(err);
        }
    }

    async createCertificate(domain: string, email: string, challengeType: 'http' | 'dns', server?: string): Promise<LetsEncrypt> {
        const baseFolder = `/tmp/letsencrypt/${domain}`
        fs.rmSync(baseFolder, { recursive: true, force: true });
        fs.mkdirSync(baseFolder, { recursive: true });

        let stdouts = '';
        const args = [
            `certonly`,
            `--manual`,
            `--preferred-challenges`, `${challengeType}`,
            `-d`, `${domain}`,
            `-m`, `${email}`,
            `--agree-tos`,
            `--manual-public-ip-logging-ok`,
            `--work-dir`, `${baseFolder}/acmework`,
            `--logs-dir`, `${baseFolder}/acmelog`,
            `--config-dir`, `${baseFolder}/acmeconf`

        ];
        if (server) {
            args.push(`--server`)
            args.push(`${server}`)
            args.push(`--no-verify-ssl`)
        }
        const prc = childprocess.spawn('certbot', args);
        let challenge: LetsEncryptChallenge | null = null;
        let processed = false;
        prc.stdout.on('data', async (data: Buffer) => {
            const str = data.toString();
            logger.info(str);
            stdouts += str;
            if (!processed && stdouts.includes('Press Enter to Continue')) {
                try {
                    challenge = await this.parseChallenge(stdouts, this.challengeFolder);
                    if (!challenge)
                        throw new Error('could not parse challenge')
                    await this.systemLogService.write({ path: '/system/letsencrypt/acmechallenge', type: 'put', val: challenge })
                    await Util.sleep(3000);
                    prc.stdin.write('\n');
                } catch (ignore) {
                    logger.error(ignore);
                    prc.kill();
                }
                processed = true;
            }

        });
        prc.stderr.on('data', (data: Buffer) => {
            const str = data.toString();
            stdouts += str;
            logger.info(str);

        })

        await new Promise((resolve, reject) => {
            let timeoutOccured = false;
            prc.on('exit', () => {
                clearTimeout(timer);
                if (stdouts.includes('The following errors were'))
                    reject('Challenge failed for domain');
                else if (timeoutOccured)
                    reject('lets encrypt timeout');
                else
                    resolve('');
            })
            let timer = setTimeout(() => {
                timeoutOccured = true;
                try {
                    prc.kill();
                } catch (ignore) {

                }
            }, 30 * 1000);//wait 30 minutes;

        });
        if (!challenge)
            throw new Error('could not parse challenge');
        const dir = `${baseFolder}/acmeconf/live/${domain}`;
        let privateFile = (await fsp.readFile(path.join(dir, 'privkey.pem'))).toString();
        let publicFile = (await fsp.readFile(path.join(dir, 'cert.pem'))).toString();
        let chainFile = (await fsp.readFile(path.join(dir, 'chain.pem'))).toString();
        let fullchainFile = (await fsp.readFile(path.join(dir, 'fullchain.pem'))).toString();

        const item: LetsEncrypt = {
            domain: domain,
            email: email,
            updateDate: new Date().toISOString(),
            challengeType: challengeType,
            privateKey: privateFile,
            publicCrt: publicFile,
            chainCrt: chainFile,
            fullChainCrt: fullchainFile,
            challenge: challenge

        };
        return item;
    }
    async renew(domain: string, email: string, server?: string) {
        const baseFolder = `/tmp/letsencrypt/${domain}`
        fs.mkdirSync(baseFolder, { recursive: true });

        let stdouts = '';
        const args = [
            `certonly`,
            `--manual`,
            `--force-renew`,
            `-d`, `${domain}`,
            `--manual-public-ip-logging-ok`,
            `--work-dir`, `${baseFolder}/acmework`,
            `--logs-dir`, `${baseFolder}/acmelog`,
            `--config-dir`, `${baseFolder}/acmeconf`

        ];
        if (server) {
            args.push(`--server`)
            args.push(`${server}`)
            args.push(`--no-verify-ssl`)
        }
        const prc = childprocess.spawn('certbot', args);
        let challenge: LetsEncryptChallenge | null = null;
        let processed = false;
        prc.stdout.on('data', async (data: Buffer) => {
            const str = data.toString();
            logger.info(str);
            stdouts += str;
            if (!processed && stdouts.includes('Press Enter to Continue')) {
                try {
                    challenge = await this.parseChallenge(stdouts, this.challengeFolder);
                    if (!challenge)
                        throw new Error('could not parse challenge')
                    await this.systemLogService.write({ path: '/system/letsencrypt/acmechallenge', type: 'put', val: challenge })
                    await Util.sleep(3000);
                    prc.stdin.write('\n');
                } catch (ignore) {
                    logger.error(ignore);
                    prc.kill();
                }
                processed = true;
            }

        });
        prc.stderr.on('data', (data: Buffer) => {
            const str = data.toString();
            stdouts += str;
            logger.info(str);

        })

        await new Promise((resolve, reject) => {
            let timeoutOccured = false;
            prc.on('exit', () => {
                clearTimeout(timer);
                if (!stdouts.includes('Congratulations! Your certificate and chain have been saved at'))
                    reject('renew failed for domain');
                else if (timeoutOccured)
                    reject('lets encrypt timeout');
                else
                    resolve('');
            })
            let timer = setTimeout(() => {
                timeoutOccured = true;
                try {
                    prc.kill();
                } catch (ignore) {

                }
            }, 30 * 1000);//wait 30 minutes;

        });
        const dir = `${baseFolder}/acmeconf/live/${domain}`;
        let privateFile = (await fsp.readFile(path.join(dir, 'privkey.pem'))).toString();
        let publicFile = (await fsp.readFile(path.join(dir, 'cert.pem'))).toString();
        let chainFile = (await fsp.readFile(path.join(dir, 'chain.pem'))).toString();
        let fullchainFile = (await fsp.readFile(path.join(dir, 'fullchain.pem'))).toString();

        const item: LetsEncrypt = {
            domain: domain,
            email: email,
            updateDate: new Date().toISOString(),
            privateKey: privateFile,
            publicCrt: publicFile,
            chainCrt: chainFile,
            fullChainCrt: fullchainFile

        };
        return item;
    }
    async parseChallenge(output: string, folder: string): Promise<LetsEncryptChallenge | null> {
        await fsp.mkdir(folder, { recursive: true });
        let lines = output.split('\n');
        lines = lines.map(x => x.trim()).filter(y => y);
        const index = lines.findIndex(x => x.startsWith('Create a file containing'));
        if (index < 0) return null;
        const hash = lines[index + 1];
        if (!hash) return null;
        const url = lines[index + 3];
        if (!url) return null;
        const filename = url.substring(url.indexOf('acme-challenge/') + 15);
        if (!filename) return null;
        await fsp.writeFile(path.join(folder, filename), hash);
        return { key: filename, value: hash, type: 'http' };


    }

}
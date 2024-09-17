import fsp from 'fs/promises';
import { glob } from 'glob';
import { logger } from '../../common';
import fs from 'fs';
import { FerrumCloudConfig } from '../../model/externalConfig';
import { ConfigService } from '../configService';
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export interface ScheduledTask {
    start(...args: any): Promise<void>;


    stop(): Promise<void>;
}

export class ClearTmpFolderTask implements ScheduledTask {

    protected timerUploadFolder: any;

    /**
     *
     */
    constructor(protected tmpFolder: string, protected interval: number = 60 * 60 * 1000, protected oldTime = 24 * 60 * 60 * 1000) {


    }
    async start(overrideInterval?: number): Promise<void> {
        this.timerUploadFolder = setIntervalAsync(async () => {
            await this.clearUploadFolder();
        }, overrideInterval || this.interval);//1 hours
    }
    async stop(): Promise<void> {
        if (this.timerUploadFolder)
            clearIntervalAsync(this.timerUploadFolder);
        this.timerUploadFolder = null;
    }

    async clearUploadFolder(oldTime = 24 * 60 * 60 * 1000) {//1 day old
        try {
            logger.info(`checking files under folder ${this.tmpFolder}`)
            const files = await glob(`${this.tmpFolder}/**`, { nodir: true });
            for (const file of files) {

                if (!file) continue;
                logger.info(`founded file ${file}`);
                const stat = await fsp.stat(file);
                if (new Date().getTime() - stat.birthtimeMs > oldTime) {
                    logger.info(`deleting old file ${file}`);
                    try {
                        await fsp.unlink(file);
                    } catch (ignore) { logger.error(ignore) }
                }
            }

        } catch (err) {
            logger.error(err);
        }
    }

}

export class ImportExternalConfigTask implements ScheduledTask {

    protected timerCheckConfigFile: any;
    protected oldTime: Date = new Date(1, 1, 1)
    /**
     *
     */
    constructor(protected interval: number = 1 * 60 * 1000, protected configService: ConfigService, protected configFile: string) {


    }
    async start(overrideInterval?: number): Promise<void> {
        this.timerCheckConfigFile = setIntervalAsync(async () => {
            await this.checkConfigFile();
        }, overrideInterval || this.interval);//1 hours
    }
    async stop(): Promise<void> {
        if (this.timerCheckConfigFile)
            clearIntervalAsync(this.timerCheckConfigFile);
        this.timerCheckConfigFile = null;
    }

    async checkConfigFile(): Promise<boolean> {//check config file
        try {
            logger.info(`checking file under folder ${this.configFile}`)
            if (fs.existsSync(this.configFile)) {
                logger.info(`founded file ${this.configFile}`);
                const stat = await fsp.stat(this.configFile);
                if (stat.mtime > this.oldTime) {
                    logger.info(`config file updated ${this.configFile}`);

                    const fileContent = await fsp.readFile(this.configFile, 'utf8');
                    const cloudConfigAsBase64String = fileContent.split('\n').find(x => x.startsWith('FERRUM_CLOUD_CONFIG='))?.split('=')[1];
                    if (!cloudConfigAsBase64String) {
                        this.oldTime = stat.mtime;
                        return false;
                    }
                    const cloudConfigAsJsonString = Buffer.from(cloudConfigAsBase64String, 'base64').toString('utf8');
                    const cloudConfig: FerrumCloudConfig = JSON.parse(cloudConfigAsJsonString);
                    const externalConfig = await this.configService.getExternalConfig();
                    if (cloudConfig.captcha && cloudConfig.captcha.externalId && !externalConfig.ids?.includes(cloudConfig.captcha?.externalId)) {
                        logger.info(`found captcha config`);
                        await this.configService.setCaptcha({ client: cloudConfig.captcha.client, server: cloudConfig.captcha.server });
                        if (!externalConfig.ids)
                            externalConfig.ids = [];
                        externalConfig.ids.push(cloudConfig.captcha.externalId);
                        await this.configService.setExternalConfig(externalConfig);

                    }
                    this.oldTime = stat.mtime;
                    return true;
                }
                else return false;
            } else
                return false;


        } catch (err) {
            logger.error(err);
            return false;
        }
    }

}
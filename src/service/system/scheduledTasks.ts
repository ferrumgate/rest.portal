import fsp from 'fs/promises';
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');
import glob from 'glob'
import { logger } from '../../common';

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
import { Util } from "../util";
import { logger } from "../common";
import { ActivityLog } from "../model/activityLog";
import { ESService, SearchActivityLogsRequest } from "./esService";
import { RedisService } from "./redisService";

const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

/**
 * @summary all system activities
 */
export class ActivityService {
    /**
     *
     */

    trimInterval: any;

    constructor(private redisService: RedisService, private esService: ESService) {
        this.trimInterval = setIntervalAsync(async () => {
            await this.trimStream();
        }, 1 * 60 * 60 * 1000)
    }


    async save(act: ActivityLog) {
        const base64 = Util.jencode(act).toString('base64url');// Buffer.from(JSON.stringify(act)).toString('base64url')
        await this.redisService.xadd('/logs/activity', { val: base64, type: 'b64' });
    }



    async trimStream(min?: string) {
        try {
            await this.redisService.xtrim('/logs/activity', min || (new Date().getTime() - 1 * 60 * 60 * 1000).toString());

        } catch (err) {
            logger.error(err);
        }
    }
    /**
     * for testing we need this
     */
    async stop() {
        if (this.trimInterval)
            clearIntervalAsync(this.trimInterval);
        this.trimInterval = null;
    }

    async search(req: SearchActivityLogsRequest) {
        return await this.esService.searchActivityLogs(req);
    }




}

import { Util } from "../../util";
import { logger } from "../../common";
import { ESService } from "../esService";
import { RedisService } from "../redisService";

import { ConfigService } from "../configService";
import { ActivityLog } from "../../model/activityLog";

const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

/**
 * @summary a class that watches activity logs and writes them to es
 */
export class ActivityLogToES {

    /**
     *
     */
    lastPos = '';
    timer: any;
    isRedisMaster = false;
    lastRedisMasterCheck = 0;
    activityStreamKey = '/activity/logs';
    es: ESService;
    redis: RedisService;
    constructor(private configService: ConfigService) {
        this.es = this.createESService();
        this.redis = this.createRedis();
    }
    createESService() {
        return new ESService(process.env.ES_HOST, process.env.ES_USER, process.env.ES_PASS);
    }

    createRedis() {
        return new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS);
    }

    async start() {
        await this.check();
        this.timer = setIntervalAsync(async () => {
            await this.check()
        }, 5000)
    }
    async stop() {
        if (this.timer)
            clearIntervalAsync(this.timer);
        this.timer = null;
    }
    async checkRedisIsMaster() {
        const now = new Date().getTime();
        //every 15 seconds
        if ((this.lastRedisMasterCheck + 15 * 1000) < now) {
            logger.info(`checking redis is master`);
            const info = await this.redis.info();
            if (info.includes("role:master")) {
                this.isRedisMaster = true;
                logger.info("redis is master");
            } else {
                this.isRedisMaster = false;
            }
            this.lastRedisMasterCheck = now;
        }
    }
    async check() {
        try {
            await this.checkRedisIsMaster();
            if (!this.isRedisMaster) {
                await Util.sleep(5000);
                return;
            }
            if (!this.lastPos) {
                const pos = await this.redis.get('/activity/logs/pos', false) as string;
                if (pos)
                    this.lastPos = pos;
                else
                    this.lastPos = '0';

            }
            while (true) {
                const items = await this.redis.xread(this.activityStreamKey, 10000, this.lastPos, 5000);
                logger.info(`activity logs getted size: ${items.length}`);
                let pushItems = [];
                let unknownItemsCount = 0;
                for (const item of items) {
                    this.lastPos = item.xreadPos;
                    try {
                        if (item.type == 'b64') {
                            const message = Buffer.from(item.data, 'base64').toString();
                            const log = JSON.parse(message) as ActivityLog;

                            const nitem = await this.es.activityCreateIndexIfNotExits(log)
                            pushItems.push(nitem);
                        } else {
                            logger.warn(`unknown type for activity log ${item.type}, skipping`);
                            unknownItemsCount++;

                        }


                    } catch (err) {
                        logger.error(err);

                    }
                }
                if (pushItems.length) {
                    await this.es.activitySave(pushItems);
                    await this.redis.set('/activity/logs/pos', this.lastPos);
                    logger.info(`activity logs written to es size: ${pushItems.length}`)
                } else
                    if (unknownItemsCount) {//save only new pos
                        await this.redis.set('/activity/logs/pos', this.lastPos);
                    }

                if (!items.length)
                    break;
            }

        } catch (err) {
            logger.error(err);
        }
    }


}
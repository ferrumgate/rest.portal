import { logger } from "../common";
import { RedisService } from "./redisService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');
/**
 * @check if redis is master or slave
 */
export class RedisWatcherService {

    timer: any;
    isMaster = false;
    private lastRedisMasterCheck = 0;
    private redis: RedisService;
    constructor(redisService?: RedisService, host?: string, pass?: string) {
        this.redis = redisService || new RedisService(host, pass);
    }
    async start() {
        await this.checkRedisIsMaster();
        this.timer = setIntervalAsync(async () => {
            await this.checkRedisIsMaster();
        }, 5000)
    }
    async stop() {
        if (this.timer)
            clearIntervalAsync(this.timer);
        this.timer = null;
    }

    async checkRedisIsMaster() {
        const now = new Date().getTime();
        try {

            //every 15 seconds
            if ((this.lastRedisMasterCheck + 15 * 1000) < now) {
                logger.info(`checking redis is master`);
                const info = await this.redis.info();
                if (info.includes("role:master")) {
                    this.isMaster = true;
                    logger.info("redis is master");
                } else {
                    this.isMaster = false;
                }

            }
        } catch (err) {
            logger.error(err);
        }
        this.lastRedisMasterCheck = now;
    }


}
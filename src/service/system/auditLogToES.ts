
import { Util } from "../../util";
import { logger } from "../../common";
import { ESService } from "../esService";
import { RedisService } from "../redisService";
import { AuditLog } from "../../model/auditLog";
import { ConfigService } from "../configService";
import { config } from "process";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

/**
 * @summary a class that watches audit logs and writes them to es
 */
export class AuditLogToES {

    /**
     *
     */
    lastPos = '';
    timer: any;
    isRedisMaster = false;
    lastRedisMasterCheck = 0;
    auditStreamKey = '/audit/logs';
    public encKey = '';
    es: ESService;
    redis: RedisService;
    constructor(private configService: ConfigService) {
        this.encKey = this.configService.getEncKey();
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
                const pos = await this.redis.get('/audit/logs/pos', false) as string;
                if (pos)
                    this.lastPos = pos;
                else
                    this.lastPos = '0';

            }
            while (true) {
                const items = await this.redis.xread(this.auditStreamKey, 10000, this.lastPos, 5000);
                logger.info(`audit logs getted size: ${items.length}`);
                let pushItems = [];
                for (const item of items) {
                    try {
                        const message = Util.decrypt(this.encKey, item.data);
                        const log = JSON.parse(message) as AuditLog;
                        this.lastPos = item.xreadPos;

                        const nitem = await this.es.auditCreateIndexIfNotExits(log)
                        pushItems.push(nitem);


                    } catch (err) {
                        logger.error(err);
                    }
                }
                if (pushItems.length) {
                    await this.es.auditSave(pushItems);
                    await this.redis.set('/audit/logs/pos', this.lastPos);
                    logger.info(`audit logs written to es size: ${pushItems.length}`)
                }
                if (!items.length)
                    break;
            }

        } catch (err) {
            logger.error(err);
        }
    }


}
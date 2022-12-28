
import { Util } from "../../util";
import { logger } from "../../common";
import { ESService, ESServiceLimited } from "../esService";
import { RedisService } from "../redisService";
import { AuditLog } from "../../model/auditLog";
import { ConfigService } from "../configService";
import { config } from "process";
import { RedisWatcherService } from "../redisWatcherService";
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
    auditStreamKey = '/logs/audit';
    public encKey = '';
    es: ESService;

    constructor(private configService: ConfigService, private redis: RedisService,
        private redisWatcher: RedisWatcherService) {
        this.encKey = this.configService.getEncKey();
        this.es = this.createESService();

    }
    createESService() {
        if (process.env.LIMITED_MODE == 'true')
            return new ESServiceLimited(process.env.ES_HOST, process.env.ES_USER, process.env.ES_PASS);
        else
            return new ESService(process.env.ES_HOST, process.env.ES_USER, process.env.ES_PASS);
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

    async check() {
        try {

            if (!this.redisWatcher.isMaster) {
                await Util.sleep(5000);
                return;
            }
            if (!this.lastPos) {
                const pos = await this.redis.get('/logs/audit/pos', false) as string;
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
                        this.lastPos = item.xreadPos;
                        const message = Util.decrypt(this.encKey, item.data, 'base64');
                        const log = JSON.parse(message) as AuditLog;
                        const nitem = await this.es.auditCreateIndexIfNotExits(log)
                        pushItems.push(nitem);


                    } catch (err) {
                        logger.error(err);
                    }
                }
                if (pushItems.length) {
                    await this.es.auditSave(pushItems);

                    logger.info(`audit logs written to es size: ${pushItems.length}`)
                }
                if (items.length)
                    await this.redis.set('/logs/audit/pos', this.lastPos);
                if (!items.length)
                    break;
            }

        } catch (err) {
            logger.error(err);
        }
    }


}
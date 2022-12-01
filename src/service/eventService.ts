const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');
import { Util } from "../util";
import { logger } from "../common";
import { ConfigEvent } from "../model/config";
import { ConfigService } from "./configService";
import { RedisService } from "./redisService";

/**
 * @summary publish config service events to redis pub/sub
 */
export class EventService {
    /**
     *
     */
    trimInterval: any;
    lastCommandNumber = 0;
    public encKey;
    constructor(private configService: ConfigService, private redisService: RedisService) {
        this.encKey = this.configService.getEncKey();
        this.trimInterval = setIntervalAsync(async () => {
            await this.trimReplication();
        }, 1 * 60 * 60 * 1000)

        this.configService.events.on('changed', async (data: ConfigEvent) => {
            try {
                let simple = { id: undefined };
                if (data.data) {
                    if (data.data.after && data.data.after.id)
                        simple.id = data.data.after.id;
                    else
                        if (data.data.before && data.data.before.id)
                            simple.id = data.data.before.id;
                }
                let simpleEvent: ConfigEvent = { type: data.type, path: data.path, data: simple }
                await this.redisService.publish(`/config/changed`, Buffer.from(JSON.stringify(simpleEvent)).toString('base64'));
            } catch (err) {
                logger.error(err);
            }

            try {
                const json = JSON.stringify(data);
                const enc = Util.encrypt(this.encKey, json);
                //const b64 = Buffer.from(json).toString('base64');
                this.lastCommandNumber++;
                await this.redisService.xadd(`/replication/config`, { data: enc }, `${new Date().getTime()}-${this.lastCommandNumber}`);

            } catch (err) {
                logger.error(err);
            }
        })

    }
    async trimReplication() {
        try {
            await this.redisService.xtrim('/replication/config', (new Date().getTime() - 1 * 60 * 60 * 1000).toString());

        } catch (err) {
            logger.error(err);
        }
    }
    async stop() {
        if (this.trimInterval)
            clearIntervalAsync(this.trimInterval);
        this.trimInterval = null;
    }
}
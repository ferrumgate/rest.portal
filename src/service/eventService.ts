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

    constructor(private configService: ConfigService, private redisService: RedisService) {

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

        })

    }

    async stop() {

    }
}
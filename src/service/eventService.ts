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
                await this.redisService.publish(`/config/changed`, JSON.stringify(data));
            } catch (err) {
                logger.error(err);
            }
        })

    }
}
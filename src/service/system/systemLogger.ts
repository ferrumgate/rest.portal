import { ConfigService } from "../configService";
import { RedisService } from "../redisService";

export interface SystemLog {
    type: string;
    val: any;
}

export class SystemLogger {
    key = '/system/logs';
    /**
     *
     */
    constructor(
        private configService: ConfigService,
        private redis: RedisService,
    ) {


    }

    async save(type: SystemLog) {

    }
}

import { ConfigService } from "./configService";
import { RedisPipelineService, RedisService } from "./redisService";
import { WatchService } from "./watchService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');
export interface SystemLog {
    type: string;
    path: string;
    val: any;
}

export class SystemLogService {
    private key = '/logs/system';

    logWatcher: WatchService;
    constructor(private redis: RedisService, private redisStream: RedisService, encryptKey: string = '', uniqueName = 'systemlog') {

        this.logWatcher = new WatchService(this.redis, this.redisStream, this.key, uniqueName + '/pos',
            new Date().getTime().toString(),
            24 * 60 * 60 * 1000,
            encryptKey);
    }

    async write(type: SystemLog, pipeline?: RedisPipelineService) {
        await this.logWatcher.write(type, pipeline);
    }

    async start() {
        await this.logWatcher.start(false);
    }
    async stop() {
        await this.logWatcher.stop(false);
    }


}

import { ConfigService } from "./configService";
import { RedisPipelineService, RedisService } from "./redisService";
import { WatchService } from "./watchService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');
export interface SystemLog {
    type: string;
    path: string;
    val: any;
    before?: any;
}
/**
 * @summary a system logger, with @see WatchService that writes logs to a redis stream
 */
export class SystemLogService {
    private key = '/logs/system';

    logWatcher: WatchService;
    constructor(private redis: RedisService, private redisStream: RedisService,
        encryptKey: string = '', uniqueName = 'systemlog') {

        this.logWatcher = new WatchService(this.redis, this.redisStream, this.key, uniqueName + '/pos',
            new Date().getTime().toString(),
            24 * 60 * 60 * 1000,
            encryptKey);
    }

    /**
     * @summary append log
     */
    async write(type: SystemLog, pipeline?: RedisPipelineService) {
        await this.logWatcher.write(type, pipeline);
    }

    /**
     * @summary start logWatcher @see WatchService
     * @param watch if true starts watching redis stream, else only starts trim functinality
     */
    async start(watch = true) {
        await this.logWatcher.start(watch);
    }

    /**
     * @summary stop logWatcher
     * @param watch if true also stop watching stream
     */
    async stop(watch = true) {
        await this.logWatcher.stop(watch);
    }

    /**
     * @summary start only watching stream
     */
    async startWatch() {

        await this.logWatcher.startWatch();
    }

    /**
     * @summary stop only watching stream
     */
    async stopWatch() {
        await this.logWatcher.stopWatch();
    }


}

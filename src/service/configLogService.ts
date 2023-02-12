import { ConfigService } from "./configService";
import { RedisPipelineService, RedisService } from "./redisService";
import { SystemLog } from "./systemLogService";
import { WatchService } from "./watchService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

/**
 * @summary a config logger, with @see WatchService that writes logs to a redis stream
 */
export class ConfigLogService {
    private key = '/logs/config';
    private isStarted = false;
    watcher: WatchService;
    constructor(private redis: RedisService, private redisStream: RedisService,
        encryptKey: string = '', uniqueName = 'configLog', logReadWaitMS = 1000) {

        this.watcher = new WatchService(this.redis, this.redisStream, this.key, uniqueName + '/pos',
            new Date().getTime().toString(),
            24 * 60 * 60 * 1000,
            encryptKey, logReadWaitMS);
    }

    /**
     * @summary append log
     */
    async write(type: SystemLog, pipeline?: RedisPipelineService) {
        await this.watcher.write(type, pipeline);
    }

    /**
     * @summary start logWatcher @see WatchService
     * @param watch if true starts watching redis stream, else only starts trim functinality
     */
    async start(watch = true) {
        await this.watcher.start(watch);
    }

    /**
     * @summary stop logWatcher
     * @param watch if true also stop watching stream
     */
    async stop(watch = true) {
        await this.watcher.stop(watch);
    }

    /**
     * @summary start only watching stream
     */
    async startWatch() {
        if (!this.isStarted)
            await this.watcher.startWatch();
        this.isStarted = true;
    }

    /**
     * @summary stop only watching stream
     */
    async stopWatch() {
        if (this.isStarted)
            await this.watcher.stopWatch();
        this.isStarted = false;
    }


}

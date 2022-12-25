import { logger } from "../common";
import { EventEmitter } from "stream";
import { RedisPipelineService, RedisService } from "./redisService";
import { Util } from "../util";
import { EncodingOption } from "fs";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export interface WatchItem<T> {
    val: T,
    time: number,
    encoding?: EncodingOption;
}

export class WatchService {
    events: EventEmitter;
    private interval: any;
    private intervalRead: any;
    private lastPostReaded = false;
    constructor(private redis: RedisService, private redisStreamService: RedisService,
        private file: string, private lastPos = new Date().getTime().toString(),
        private trimTime = 24 * 60 * 60 * 1000,
        private encKey?: string

    ) {
        this.events = new EventEmitter();

    }

    async startWatch() {

        this.intervalRead = await setIntervalAsync(async () => {

            await this.read()
        }, 100);

    }
    async start(startWatch = true) {
        this.interval = await setIntervalAsync(async () => {
            await this.trim();
        }, this.trimTime);
        if (startWatch)
            await this.startWatch();
    }
    async stop() {
        if (this.interval)
            clearIntervalAsync(this.interval);
        this.interval = null;
        if (this.intervalRead)
            clearIntervalAsync(this.intervalRead);
        this.intervalRead = null;
    }

    async write(data: any, redisPipeLine?: RedisPipelineService) {
        if (data == null || data == undefined) return;
        let dataStr = JSON.stringify(data);
        let base64 = '';
        if (this.encKey && process.env.NODE_ENV !== 'development') {
            base64 = Util.encrypt(this.encKey, dataStr, 'base64');

        } else {
            base64 = Buffer.from(dataStr).toString('base64');;
        }
        if (redisPipeLine)
            await redisPipeLine.xadd(this.file, { val: base64, time: new Date().getTime(), encoding: 'base64' } as WatchItem<string>);
        else
            await this.redis.xadd(this.file, { val: base64, time: new Date().getTime(), encoding: 'base64' } as WatchItem<string>);
    }
    async read() {
        try {
            if (!this.lastPostReaded) {
                this.lastPos = await this.redis.get(`${this.file}/pos`, false) || this.lastPos;
                this.lastPostReaded = true;
            }
            while (true) {
                const items = await this.redis.xread(this.file, 10000, this.lastPos, 1000);
                logger.info(`${this.file} logs getted size: ${items.length}`);
                for (const item of items) {
                    try {
                        this.lastPos = item.xreadPos;
                        let dataStr = (this.encKey && process.env.NODE_ENV !== 'development') ? Util.decrypt(this.encKey, item.val, 'base64') : Buffer.from(item.val, 'base64').toString();
                        const data = JSON.parse(dataStr);
                        const time = Number(item.time);
                        this.events.emit('data', { val: data, time: time } as WatchItem<string>)


                    } catch (err) {
                        logger.error(err);
                    }
                }
                if (items.length)
                    await this.redis.set(`${this.file}/pos`, this.lastPos);
                if (!items.length)
                    break;
            }
        } catch (err) {
            logger.error(err);
        }
    }
    async trim() {
        try {
            logger.info(`trimming log file ${this.file}`);
            await this.redis.expire(this.file, this.trimTime * 2);
            await this.redis.xtrim(this.file, (new Date().getTime() - this.trimTime).toString());
        } catch (err) {
            logger.error(err);
        }
    }
}
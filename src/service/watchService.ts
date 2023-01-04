import { logger } from "../common";

import { RedisPipelineService, RedisService } from "./redisService";
import { Util } from "../util";
import { EncodingOption } from "fs";
import EventEmitter from "node:events";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export interface WatchItem<T> {
    val: T,
    time: number,
    encoding?: EncodingOption;
}
/**
 * @summary this class works like `tail -f ` on a queue,
 * read and writes datas to a queue and watches 
 */
export class WatchService {
    events: EventEmitter;
    private interval: any;
    private intervalRead: any;
    private lastPostReaded = false;
    constructor(private redis: RedisService, private redisStreamService: RedisService,
        private file: string, private posFollowKey = 'pos',
        private lastPos = new Date().getTime().toString(),
        private trimTime = 24 * 60 * 60 * 1000,
        private encKey?: string

    ) {
        this.events = new EventEmitter();

    }

    // start tail -f
    async startWatch() {

        this.intervalRead = await setIntervalAsync(async () => {
            await this.read()
        }, 100);

    }
    // start tail -f and trim
    async start(startWatch = true) {
        this.interval = await setIntervalAsync(async () => {
            await this.trim();
        }, this.trimTime);
        if (startWatch)
            await this.startWatch();
    }
    // stop tail and trim
    async stop(stopWatch = true) {
        if (this.interval)
            clearIntervalAsync(this.interval);
        this.interval = null;
        if (stopWatch) {
            await this.stopWatch();
        }
    }
    // stop tail -f 
    async stopWatch() {
        if (this.intervalRead)
            clearIntervalAsync(this.intervalRead);
        this.intervalRead = null;
    }

    /**
     * @summary write any data to the end of queue
     */
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
    //position key
    private posKey() {
        return `${this.file}${this.posFollowKey.startsWith('/') ? this.posFollowKey : '/' + this.posFollowKey}`;
    }

    /**
     * @summary  read elements from last position 
     */
    async read() {
        try {
            if (!this.lastPostReaded) {
                this.lastPos = await this.redis.get(this.posKey(), false) || this.lastPos;
                this.lastPostReaded = true;
            }
            while (true) {
                const items = await this.redisStreamService.xread(this.file, 10000, this.lastPos, 1000);
                if (items.length)
                    logger.info(`${this.file} logs getted size: ${items.length}`);
                for (const item of items) {
                    try {
                        this.lastPos = item.xreadPos;
                        let dataStr = (this.encKey && process.env.NODE_ENV !== 'development') ? Util.decrypt(this.encKey, item.val, 'base64') : Buffer.from(item.val, 'base64').toString();
                        const data = JSON.parse(dataStr);
                        const time = Number(item.time);
                        this.events.emit('data', { val: data, time: time } as WatchItem<any>)


                    } catch (err) {
                        logger.error(err);
                    }
                }
                if (items.length) {
                    const pipe = await this.redis.multi();
                    await pipe.set(this.posKey(), this.lastPos);
                    await pipe.expire(this.posKey(), 7 * 24 * 60 * 60 * 1000);
                    await pipe.exec();
                }
                if (!items.length)
                    break;
            }
        } catch (err) {
            logger.error(err);
        }
    }

    /**
     * @summary trims queue with @param trimTime
     */
    async trim(min = 0) {
        try {
            logger.info(`trimming log file ${this.file}`);
            await this.redis.expire(this.file, this.trimTime * 2);
            await this.redis.xtrim(this.file, (new Date().getTime() - (min || this.trimTime)).toString());
        } catch (err) {
            logger.error(err);
        }
    }
}
import { logger } from "../common";
import { EventEmitter } from "stream";
import { RedisService } from "./redisService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export class WatchService {
    events: EventEmitter;
    private interval: any;
    private intervalRead: any;
    private lastPostReaded = false;
    constructor(private redis: RedisService, private redisStreamService: RedisService,
        private file: string, private lastPos = '$', private trimTime = 24 * 60 * 60 * 1000

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

    async write(data: any) {
        if (data == null || data == undefined) return;
        const base64 = Buffer.from(JSON.stringify(data)).toString('base64')
        await this.redis.xadd(this.file, { data: base64, time: new Date().getTime(), type: 'b64' });
    }
    async read() {
        try {
            if (this.lastPostReaded) {
                this.lastPos = await this.redis.get(`${this.file}/pos`, false) || this.lastPos;
                this.lastPostReaded = true;
            }
            while (true) {
                const items = await this.redis.xread(this.file, 10000, this.lastPos, 1000);
                logger.info(`${this.file} logs getted size: ${items.length}`);
                for (const item of items) {
                    try {
                        this.lastPos = item.xreadPos;
                        const data = JSON.parse(Buffer.from(item.data, 'base64').toString());
                        const time = Number(item.time);
                        this.events.emit('data', { val: data, time: time })


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
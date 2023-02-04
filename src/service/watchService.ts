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
    isWorking = true;
    constructor(protected redis: RedisService, protected redisStreamService: RedisService,
        protected file: string, protected posFollowKey = 'pos',
        protected lastPos = new Date().getTime().toString(),
        protected trimTime = 24 * 60 * 60 * 1000,
        protected encKey?: string,
        protected readWriteWait = 1000
    ) {
        this.events = new EventEmitter();

    }

    // start tail -f
    async startWatch() {

        this.intervalRead = setIntervalAsync(async () => {
            await this.read()
        }, 100);

    }
    // start tail -f and trim
    async start(startWatch = true) {
        this.interval = setIntervalAsync(async () => {
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
        this.isWorking = false;
    }

    /**
     * @summary write any data to the end of queue
     */
    async write(data: any, redisPipeLine?: RedisPipelineService) {
        if (data == null || data == undefined) return;
        let dataStr = Util.jencode(data);//  JSON.stringify(data);
        let base64 = '';
        if (this.encKey) {
            base64 = Util.jencrypt(this.encKey, dataStr).toString('base64url');

        } else {
            base64 = dataStr.toString('base64url');
        }
        if (redisPipeLine)
            await redisPipeLine.xadd(this.file, { val: base64, time: new Date().getTime(), encoding: 'base64url' } as WatchItem<string>);
        else
            await this.redis.xadd(this.file, { val: base64, time: new Date().getTime(), encoding: 'base64url' } as WatchItem<string>);
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
            while (this.isWorking) {
                const items = await this.redisStreamService.xread(this.file, 10000, this.lastPos, this.readWriteWait);
                if (items.length)
                    logger.info(`${this.file} logs getted size: ${items.length}`);
                for (const item of items) {
                    try {
                        this.lastPos = item.xreadPos;
                        //let dataStr = (this.isEncrypted && this.encKey && process.env.NODE_ENV !== 'development') ? Util.decrypt(this.encKey, item.val, 'base64url') : Buffer.from(item.val, 'base64url').toString();
                        let dataStr = (this.encKey) ? Util.jdecrypt(this.encKey, Buffer.from(item.val, 'base64url')) : Buffer.from(item.val, 'base64url');
                        const data = Util.jdecode(dataStr);// JSON.parse(dataStr);
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

export class WatchBufferedWriteService extends WatchService {
    items: any[] = [];
    timerWrite: any;
    /**
     *
     */

    override async start(startWatch?: boolean): Promise<void> {
        await super.start(startWatch);
        this.timerWrite = setIntervalAsync(async () => {
            await this.pushAllData();
        }, this.readWriteWait);
    }

    override async write(data: any, redisPipeLine?: RedisPipelineService | undefined): Promise<void> {
        this.items.push(data);
    }

    async pushAllData() {
        try {
            if (!this.items.length)
                return;
            if (new Date().getTime() % 5 == 0)//some times log
                logger.info(`watch buffered write ${this.items.length}`);
            const pipeline = await this.redis.multi();
            let counter = 0;
            for (const item of this.items) {
                await super.write(item, pipeline);
                counter++;
            }
            await pipeline.exec();
            this.items.splice(0, counter);
        } catch (err) {
            logger.error(err);
        }
    }


}


export class WatchGroupService extends WatchService {
    /**
     *
     */
    private groupCreated = false;
    constructor(
        protected redis: RedisService, protected redisStreamService: RedisService,
        protected readGroupName = 'watchGroup',
        protected readConsumerName = 'watchConsumer',
        protected file: string,
        protected lastPos = new Date().getTime().toString(),
        protected trimTime = 24 * 60 * 60 * 1000,
        protected encKey: string = '',
        protected readWriteWait = 1000,
        protected onData?: (data: any[]) => Promise<void>

    ) {
        super(
            redis, redisStreamService, file, '', lastPos, trimTime, encKey, readWriteWait

        )

    }


    async createConsumerGroup() {
        try {
            if (this.groupCreated) return;
            const groups = await this.redis.xinfoGroups(this.file);
            if (!groups.find(x => x.name == this.readGroupName))
                await this.redis.xgroupCreate(this.file, this.readGroupName, '0');
            this.groupCreated = true;
        } catch (err) {
            logger.error(err);
        }
    }

    /**
     * @summary  read elements from last position 
     */
    override async read() {
        try {
            await this.createConsumerGroup();
            while (this.isWorking) {
                const items = await this.redisStreamService.xreadGroup(this.file, this.readGroupName, this.readConsumerName, 10000, this.readWriteWait);
                if (items.length)
                    logger.info(`${this.file} logs getted size: ${items.length}`);
                let ids = [];
                let retItems = [];
                for (const item of items) {
                    try {
                        this.lastPos = item.xreadPos;
                        ids.push(item.xreadPos);
                        //let dataStr = (this.isEncrypted && this.encKey && process.env.NODE_ENV !== 'development') ? Util.decrypt(this.encKey, item.val, 'base64url') : Buffer.from(item.val, 'base64url').toString();
                        let dataStr = (this.encKey) ? Util.jdecrypt(this.encKey, Buffer.from(item.val, 'base64url')) : Buffer.from(item.val, 'base64url');
                        const data = Util.jdecode(dataStr);// JSON.parse(dataStr);
                        const time = Number(item.time);
                        let retItem = { val: data, time: time } as WatchItem<any>;
                        this.events.emit('data', retItem)
                        retItems.push(retItem);

                    } catch (err) {
                        logger.error(err);
                    }
                }
                if (ids.length) {
                    if (retItems.length && this.onData)
                        await this.onData(retItems);
                    await this.redis.xack(this.file, this.readGroupName, ids);
                }
                if (!items.length)
                    break;
            }
        } catch (err) {
            logger.error(err);
        }
    }




}
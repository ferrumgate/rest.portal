import { Redis } from "ioredis";
import { logger } from "../common";
import { EventEmitter } from "stream";
import { Util } from "../util";
import { RedisService } from "./redisService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

export class RedLockService {


    randomKey: string;
    public events: EventEmitter;
    protected interval: any;
    isLocked = false;
    protected lastSuccessTime = 0;
    private resourceKey = '';
    constructor(private redis: RedisService) {

        this.randomKey = Util.randomNumberString();
        this.events = new EventEmitter;
    }

    async getKey() {
        return this.randomKey;
    }

    async lock(resource: string, ttl = 10000, check = 5000) {
        if (!this.interval) {
            await this.tryLock(resource, ttl);
            this.interval = setIntervalAsync(async () => {
                await this.tryLock(resource, ttl)
            }, check);
        }
    }
    async tryLock(resource: string, ttl: number, throwErr = false, tryCount = 4, tryTTL = 500) {
        try {
            this.resourceKey = resource;
            tryCount = this.isLocked ? 1 : tryCount;
            while (tryCount) {
                tryCount--;
                await this.redis.setnx(resource, this.randomKey, ttl);
                const val = await this.redis.get(resource, false) as string;
                if (val == this.randomKey) {
                    await this.redis.expire(resource, ttl);
                    this.lastSuccessTime = new Date().getTime();
                    //wait a little for a better experience
                    if (!this.isLocked && !tryCount) {
                        this.isLocked = true;
                        this.events.emit('acquired');
                    }

                } else {
                    console.log(`${this.resourceKey} could not locked with ${this.randomKey}`)
                    await this.release(false);
                }
                if (tryCount)
                    await Util.sleep(ttl < tryTTL ? ttl / 2 : tryTTL);
            }
            if (!this.isLocked && throwErr)
                throw new Error(`${resource} lock could not acquired`);
        } catch (err) {

            await this.release(false);
            logger.error(err);
            if (throwErr)
                throw err;
        }
    }
    async release(stop = true) {
        try {
            if (this.isLocked) {
                this.isLocked = false;
                this.lastSuccessTime = 0;
                await this.redis.delete(this.resourceKey);
                this.events.emit('released');
            }
            if (stop) {
                if (this.interval)
                    clearIntervalAsync(this.interval);
                this.interval = null;
            }
        } catch (err) {
            logger.error(err);
        }
    }

}
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
    protected isLockedTime = 0;
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
    protected async tryLock(resource: string, ttl: number) {
        try {
            this.resourceKey = resource;
            await this.redis.setnx(resource, this.randomKey, ttl);
            const val = await this.redis.get(resource, false) as string;
            if (val == this.randomKey) {
                if (!this.isLockedTime) {//lock is successfull
                    this.isLockedTime = new Date().getTime();
                }
                this.lastSuccessTime = new Date().getTime();

                if (!this.isLocked && this.lastSuccessTime - this.isLockedTime > 2 * ttl) {
                    this.isLocked = true;
                    this.events.emit('acquired');
                }
            } else {

                await this.release(false);
            }
        } catch (err) {

            await this.release(false);
            logger.error(err);

        }
    }
    async release(stop = true) {
        if (this.isLocked) {
            this.isLocked = false;
            this.randomKey = Util.randomNumberString(16);
            this.lastSuccessTime = 0;
            this.isLockedTime = 0;
            await this.redis.delete(this.resourceKey);
            this.events.emit('released');
        }
        if (stop) {
            if (this.interval)
                clearIntervalAsync(this.interval);
            this.interval = null;
        }
    }

}
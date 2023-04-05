
import { Redis } from "ioredis";
import EventEmitter from "node:events";
import { logger } from "../common";
import { Util } from "../util";
import { RedisService } from "./redisService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

/**
 * @summary A simple RedLock implementation
 * 
 */
export class RedLockService {


    randomKey: string;
    public events: EventEmitter;
    protected interval: any;
    isLocked = false;
    protected lastSuccessTime = 0;
    private resourceKey = '';
    constructor(private redis: RedisService) {

        this.randomKey = Util.randomNumberString(16);
        this.events = new EventEmitter;
    }

    async getKey() {
        return this.randomKey;
    }

    /**
     * @summary start a try for locking, and continue to try or refresh lock
     * @param resource name like /lock/leader/election/for/elastic/logs
     * @param ttl resource expire time in ms
     * @param check every ms, try to acquire or refresh if acquired
     * @param tryCount if lock is aquired, then try this count and check again if we really locked
     * @param tryTTL try every ms we really locked
     */
    async lock(resource: string, ttl = 10000, check = 5000, tryCount = 4, tryTTL = 500) {
        if (!this.interval) {
            await this.tryLock(resource, ttl, false, tryCount, tryTTL);
            this.interval = setIntervalAsync(async () => {
                await this.tryLock(resource, ttl, false, tryCount, tryTTL)
            }, check);
        }
    }
    /**
     * @summary just try to lock once , if success then emits acquired
     * @param resource name like /lock/leader/election/for/elastic/logs
     * @param ttl resource expire time in ms
     * @param check every ms, try to acquire or refresh if acquired
     * @param tryCount if lock is aquired, then try this count and check again if we really locked
     * @param tryTTL try every ms we really locked
     */
    async tryLock(resource: string, ttl: number, throwErr = false, tryCount = 4, tryTTL = 500) {
        try {
            this.resourceKey = resource;
            tryCount = this.isLocked ? 1 : tryCount;
            while (tryCount) {
                tryCount--;
                await this.redis.setnx(this.resourceKey, this.randomKey, ttl);
                const val = await this.redis.get(this.resourceKey, false) as string;
                if (val == this.randomKey) {
                    await this.redis.expire(this.resourceKey, ttl);
                    this.lastSuccessTime = new Date().getTime();
                    //wait a little for a better experience
                    if (!this.isLocked && !tryCount) {
                        this.isLocked = true;
                        logger.info(`${this.resourceKey} locked with ${this.randomKey}`)
                        this.events.emit('acquired');
                    }

                } else {
                    logger.warn(`${this.resourceKey} could not locked with ${this.randomKey}`)
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
    /**
     * @summary release lock if we acquired
     * @param stop 
     */
    async release(stop = true) {
        try {
            if (stop) {
                if (this.interval)
                    clearIntervalAsync(this.interval);
                this.interval = null;
            }
            if (this.isLocked) {
                this.isLocked = false;
                this.lastSuccessTime = 0;
                await this.redis.delete(this.resourceKey);
                this.events.emit('released');
            }

        } catch (err) {
            logger.error(err);
        }
    }

}
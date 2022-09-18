import Redis from "ioredis";
import { logger } from "../common";
import { ErrorCodes, RestfullException } from "../restfullException";
import { ConfigService } from "./configService";
import { RedisService } from "./redisService";

/**
 * ratelimit check with redis
 */
export class RateLimitService {
    protected redis: RedisService;
    protected baseLimit: number = 10;
    constructor(private config: ConfigService, redis?: RedisService,) {
        this.redis = redis || new RedisService(process.env.REDIS_HOST || 'localhost:6379', process.env.REDIS_PASS);
        this.baseLimit = Number(process.env.BASE_RATE_LIMIT) || 10;

    }
    async check(ip: string, what: string, max?: number) {
        let maxlimit = max || this.baseLimit;
        const minute = new Date().getUTCMinutes();
        const key = `/ratelimit/${what}/${ip}/${minute}`;
        logger.info(`checking ratelimit for ${key} max:${max}`);
        const exists = await this.redis.get(key, false);
        if (exists == null || exists == undefined) {
            await this.redis.set(key, 0, { ttl: 60 * 1000 });
        }
        const value = await this.redis.incr(key);
        logger.info(`checking ratelimit for ${key} current:${value} max:${max}`);
        if (value > maxlimit) {
            logger.warn(`too many request from ${ip} for ${what}`)
            throw new RestfullException(429, ErrorCodes.ErrTooManyRequests, 'too many requests');
        }

    }
}


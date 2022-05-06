
import * as IORedis from 'ioredis';

/**
 * redis wrappers
 */
export class RedisPipelineService {
    private pipeline: IORedis.ChainableCommander;
    constructor(redis: IORedis.Redis | IORedis.Cluster) {
        this.pipeline = redis.multi();

    }
    async exec(): Promise<any> {
        return await this.pipeline.exec();
    }

    async discard(): Promise<void> {
        await this.pipeline.discard();
    }

    async select(database: number): Promise<RedisPipelineService> {

        this.pipeline = await this.pipeline.select(database);
        return this;

    }
    async set(key: string, value: any, options?: any): Promise<RedisPipelineService> {

        let valueStr = value;
        if (typeof value !== 'string') {
            valueStr = JSON.stringify(value);
        }
        if (!options || !options.ttl)
            this.pipeline = await this.pipeline.set(key, valueStr)
        else
            this.pipeline = await this.pipeline.set(key, valueStr, 'PX', options.ttl);

        return this;

    }
    async get<T>(key: string, parse = true): Promise<RedisPipelineService> {

        this.pipeline = await this.pipeline.get(key) as any;
        return this;
    }

    async remove(key: string): Promise<RedisPipelineService> {

        this.pipeline = await this.pipeline.del(key)
        return this;

    }

    async containsKey(key: string): Promise<RedisPipelineService> {

        this.pipeline = await this.pipeline.exists(key);
        return this;
    }
    async incr(key: string): Promise<RedisPipelineService> {
        this.pipeline = await this.pipeline.incr(key);
        return this;
    }
    async incrby(key: string, val: number): Promise<RedisPipelineService> {
        this.pipeline = await this.pipeline.incrby(key, val);
        return this;
    }
    async decr(key: string): Promise<RedisPipelineService> {
        this.pipeline = await this.pipeline.decr(key);
        return this;
    }
    async decrby(key: string, val: number): Promise<RedisPipelineService> {
        this.pipeline = await this.pipeline.decrby(key, val);
        return this;
    }
    async expire(key: string, seconds: number): Promise<RedisPipelineService> {
        this.pipeline = await this.pipeline.pexpire(key, seconds);
        return this;

    }

    async persist(key: string): Promise<RedisPipelineService> {
        this.pipeline = await this.pipeline.persist(key);
        return this;

    }
    async ttl(key: string): Promise<RedisPipelineService> {
        this.pipeline = await this.pipeline.pttl(key)
        return this;
    }
}
export class RedisService {

    private redis: IORedis.Redis | IORedis.Cluster;

    constructor(private host?: string, private type: 'single' | 'cluster' | 'sentinel' = 'single') {
        this.redis = this.createRedisClient();

    }


    private createRedisClient(options?: any): IORedis.Redis | IORedis.Cluster {


        let hosts: { host: string, port: number }[] = [];

        let parts = this.host?.split(',') || [];
        for (let i = 0; i < parts.length; ++i) {
            let splitted = parts[i].split(':');
            let redishost = splitted.length > 0 ? splitted[0] : 'localhost';
            let redisport = splitted.length > 1 ? Number(splitted[1]) : 6379
            hosts.push({ host: redishost, port: redisport });
        }
        if (!hosts.length) {
            hosts.push({ host: 'localhost', port: 6379 });
        }

        switch (this.type) {
            case 'single':
                let redis = new IORedis.default({
                    host: hosts[0].host,
                    port: hosts[0].port,
                    connectTimeout: 5000,
                    lazyConnect: true,
                    maxRetriesPerRequest: 5
                });
                return redis;

            case 'sentinel':
                let sentinel = new IORedis.default({
                    sentinels: hosts,
                    connectTimeout: 5000,
                    lazyConnect: true,
                    maxRetriesPerRequest: 5
                });
                return sentinel;
            case 'cluster':
                let cluster = new IORedis.Cluster(hosts, {

                    lazyConnect: true,
                    redisOptions: { connectTimeout: 5000, maxRetriesPerRequest: 5 }
                });
                return cluster;


            default:
                throw new Error(`unknown redis type ${this.type}`);
        }

    }

    async select(database: number): Promise<any> {

        return await this.redis.select(database);

    }
    async set(key: string, value: any, options?: any): Promise<void> {

        let valueStr = value;
        if (typeof value !== 'string' && typeof value !== 'number') {
            valueStr = JSON.stringify(value);
        }
        if (!options || !options.ttl)
            await this.redis.set(key, valueStr)
        else
            await this.redis.set(key, valueStr, 'PX', options.ttl);

    }
    async get<T>(key: string, parse = true): Promise<T | null | undefined> {

        let x = await this.redis.get(key) as any;
        if (parse && x)
            return JSON.parse(x) as T;
        return x;
    }

    async remove(key: string): Promise<number> {

        return await this.redis.del(key)

    }

    async containsKey(key: string): Promise<boolean> {

        return (await this.redis.exists(key)) == 1;
    }
    async incr(key: string): Promise<number> {
        return await this.redis.incr(key);
    }
    async incrby(key: string, val: number): Promise<number> {
        return await this.redis.incrby(key, val);
    }
    async decr(key: string): Promise<number> {
        return await this.redis.decr(key);
    }
    async decrby(key: string, val: number): Promise<number> {
        return await this.redis.decrby(key, val);
    }
    async expire(key: string, seconds: number): Promise<void> {
        await this.redis.pexpire(key, seconds);

    }

    async persist(key: string): Promise<void> {
        await this.redis.persist(key);

    }
    async ttl(key: string): Promise<number> {
        return await this.redis.pttl(key)
    }
    async multi(): Promise<RedisPipelineService> {
        return new RedisPipelineService(this.redis);
    }

    async flushAll(): Promise<void> {
        await this.redis.flushall();
    }
    async disconnect() {
        await this.redis.disconnect();
    }
    async connect() {
        await this.redis.connect(() => { });
    }
}


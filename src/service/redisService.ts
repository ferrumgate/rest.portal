
import * as IORedis from 'ioredis';
/**
 * redis wrappers
 */
export class RedisPipelineService {
    protected pipeline: IORedis.ChainableCommander;
    constructor(redis: IORedis.Redis | IORedis.Cluster) {
        this.pipeline = redis.multi();

    }
    async exec(): Promise<any> {
        const results = await this.pipeline.exec();
        return results?.map(x => x[1]);
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
    async delete(key: string): Promise<RedisPipelineService> {

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
    async expire(key: string, milisecond: number): Promise<RedisPipelineService> {
        this.pipeline = await this.pipeline.pexpire(key, milisecond);
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
    async hget(key: string, field: string): Promise<RedisPipelineService> {

        this.pipeline = await this.pipeline.hget(key, field);
        return this;

    }
    async hgetAll(key: string): Promise<RedisPipelineService> {

        this.pipeline = await this.pipeline.hgetall(key);
        return this;

    }

    async hset(key: string, values: any): Promise<RedisPipelineService> {

        this.pipeline = await this.pipeline.hset(key, values);
        return this;

    }

    async xadd(key: string, arg: any, id?: string) {
        let arr = Object.entries(arg).filter((key, value) => {
            if (typeof value == 'string') return true
            if (typeof value == "number") return true
            return false;
        }).map((x: any[]) => {

            return [x[0] as IORedis.RedisValue, x[1].toString() as IORedis.RedisValue]
        }).flat();
        arr.unshift(id ? id : '*');
        this.pipeline = await this.pipeline.xadd(key, ...arr);
        return this;
    }


}
export class RedisService {


    protected redis: IORedis.Redis | IORedis.Cluster;

    constructor(protected host?: string, protected password: string | undefined = undefined, protected type: 'single' | 'cluster' | 'sentinel' = 'single') {
        this.redis = this.createRedisClient(host, password, type);

    }


    protected createRedisClient(host?: string, password: string | undefined = undefined, type: 'single' | 'cluster' | 'sentinel' = 'single'): IORedis.Redis | IORedis.Cluster {


        let hosts: { host: string, port: number }[] = [];

        let parts = host?.split(',') || [];
        for (let i = 0; i < parts.length; ++i) {
            let splitted = parts[i].split(':');
            let redishost = splitted.length > 0 ? splitted[0] : 'localhost';
            let redisport = splitted.length > 1 ? Number(splitted[1]) : 6379
            hosts.push({ host: redishost, port: redisport });
        }
        if (!hosts.length) {
            hosts.push({ host: 'localhost', port: 6379 });
        }

        switch (type) {
            case 'single':
                let redis = new IORedis.default({
                    host: hosts[0].host,
                    port: hosts[0].port,
                    connectTimeout: 5000,
                    password: password,
                    lazyConnect: true,
                    maxRetriesPerRequest: 5,
                });
                return redis;

            case 'sentinel':
                let sentinel = new IORedis.default({
                    sentinels: hosts,
                    connectTimeout: 5000,
                    lazyConnect: true,
                    password: password,
                    maxRetriesPerRequest: 5
                });
                return sentinel;
            case 'cluster':
                let cluster = new IORedis.Cluster(hosts, {

                    lazyConnect: true,
                    redisOptions: { connectTimeout: 5000, maxRetriesPerRequest: 5, password: password }
                });
                return cluster;


            default:
                throw new Error(`unknown redis type ${type}`);
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
    async scan(keyPattern: string, cursor: string, count: number = 1000, type?: string) {
        if (type)
            return await this.redis.scan(cursor, "MATCH", keyPattern, 'COUNT', count, "TYPE", type,);
        else
            return await this.redis.scan(cursor, "MATCH", keyPattern, 'COUNT', count,);
    }

    async remove(key: string): Promise<number> {

        return await this.redis.del(key)

    }
    async delete(key: string): Promise<number> {

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
    async expire(key: string, milisecond: number): Promise<void> {
        await this.redis.pexpire(key, milisecond);

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

    async hset(key: string, values: any): Promise<number> {

        return await this.redis.hset(key, values)

    }
    async hget(key: string, field: string): Promise<string | null> {

        return await this.redis.hget(key, field);

    }
    async hgetAll(key: string): Promise<Record<string, string>> {

        return await this.redis.hgetall(key);

    }
    async hmgetAll(key: string, fields: string[]): Promise<Record<string, string> | null> {

        const arr = await this.redis.hmget(key, ...fields);
        if (!arr) return null;
        let obj = {} as any;
        for (let i = 0; i < fields.length; ++i) {
            obj[fields[i]] = arr[i];
        }
        return obj;

    }


    async publish(channel: string, msg: any) {
        return await this.redis.publish(channel, typeof (msg) !== 'string' ? JSON.stringify(msg) : msg);
    }

    async sadd(key: string, value: string | number | any[]) {
        if (Array.isArray(value))
            return await this.redis.sadd(key, ...(value as []));
        else
            return await this.redis.sadd(key, value);
    }
    async sremove(key: string, value: string | number | any[]) {
        if (Array.isArray(value))
            return await this.redis.srem(key, ...(value as []));
        else
            return await this.redis.srem(key, value);
    }
    async sismember(key: string, value: string | number) {
        return await this.redis.sismember(key, value);
    }

    async subscribe(channel: string) {
        return this.redis.subscribe(channel);
    }


    async onMessage(callback: (channel: string, message: string) => void) {
        await this.redis.on('message', async (channel, message) => {
            await callback(channel, message);
        })
    }

    async xadd(key: string, arg: any, id?: string) {
        let arr = Object.entries(arg).filter((key, value) => {
            if (typeof value == 'string') return true
            if (typeof value == "number") return true
            return false;
        }).map((x: any[]) => {

            return [x[0] as IORedis.RedisValue, x[1].toString() as IORedis.RedisValue]
        }).flat();
        arr.unshift(id ? id : '*');
        return await this.redis.xadd(key, ...arr);
    }

    async xread(key: string, count: number, pos: string, readtimeout: number) {
        const result = await this.redis.xread("COUNT", count, 'BLOCK', readtimeout, 'STREAMS', key, pos ? pos : '0');
        if (!result?.length || !result[0][1]) return [];
        const items = result[0][1];
        return items.map(x => {
            let obj = {
                xreadPos: x[0],
            } as any;
            for (let i = 0; i < x[1].length; i += 2) {
                if (i + 1 < x[1].length) {
                    obj[x[1][i]] = x[1][i + 1];
                }
            }
            return obj;
        })

    }

    async xreadmulti(search: { key: string, pos: string }[], count: number, readtimeout: number) {
        let streams: any = [];
        search.forEach(x => streams.push(x.key));
        search.forEach(x => streams.push(x.pos));
        const result = await this.redis.xread("COUNT", count, 'BLOCK', readtimeout, 'STREAMS', ...streams);
        if (!result?.length) return [];
        let finalList = [];
        for (let x = 0; x < result.length; ++x) {
            const channel = result[x][0];
            const items = result[x][1];
            let retItems = items.map(x => {
                let obj = {
                    xreadPos: x[0],
                } as any;
                for (let i = 0; i < x[1].length; i += 2) {
                    if (i + 1 < x[1].length) {
                        obj[x[1][i]] = x[1][i + 1];
                    }
                }
                return obj;
            })
            finalList.push({ channel: channel, items: retItems });

        }
        return finalList;

    }

    async xinfo(key: string) {
        let arr = await this.redis.xinfo('STREAM', key) as [];
        let info = {} as { [key: string]: any; };
        for (let i = 0; i < arr.length; i += 2) {
            if (i + 1 < arr.length) {
                info[arr[i]] = arr[i + 1];
            }
        }
        return info;
    }
    async cliendId() {
        return await this.redis.client('ID');
    }
    async trackBroadCast(cliendId: number, prefix?: string[]) {
        if (!prefix?.length)
            return await this.redis.client('TRACKING', 'ON', 'REDIRECT', cliendId, 'BCAST');
        else {
            let prefixList = prefix.map(x => ['PREFIX', x]).flat();
            return await this.redis.client('TRACKING', 'ON', 'REDIRECT', cliendId, 'BCAST', ...prefixList);
        }
    }

    async info() {
        return await this.redis.info();
    }
    async xtrim(key: string, pos: string) {
        return await this.redis.xtrim(key, 'MINID', pos);
    }

    async lpush(key: string, values: string[]) {
        return await this.redis.lpush(key, ...values);
    }
    async smembers(key: string) {
        return await this.redis.smembers(key);
    }


}



export class RedisServiceManuel extends RedisService {
    /**
     *
     */


    isClosedManuel = false;
    constructor(protected host?: string, protected password: string | undefined = undefined, protected type: 'single' | 'cluster' | 'sentinel' = 'single', private onClose?: () => Promise<void>) {
        super(host, password, type);

        const onCloseFunc = async () => {
            if (this.onClose && !this.isClosedManuel)
                await this.onClose();
            this.redis.removeListener('close', onCloseFunc);
        }
        this.redis.on('close', onCloseFunc);
    }
    override disconnect(): Promise<void> {
        this.isClosedManuel = true;
        return super.disconnect();
    }

    protected override createRedisClient(host?: string | undefined, password?: string | undefined, type?: "single" | "cluster" | "sentinel"): IORedis.Redis | IORedis.Cluster {

        let hosts: { host: string, port: number }[] = [];

        let parts = host?.split(',') || [];
        for (let i = 0; i < parts.length; ++i) {
            let splitted = parts[i].split(':');
            let redishost = splitted.length > 0 ? splitted[0] : 'localhost';
            let redisport = splitted.length > 1 ? Number(splitted[1]) : 6379
            hosts.push({ host: redishost, port: redisport });
        }
        if (!hosts.length) {
            hosts.push({ host: 'localhost', port: 6379 });
        }

        switch (type) {
            case 'single':
                let redis = new IORedis.default({
                    host: hosts[0].host,
                    port: hosts[0].port,
                    connectTimeout: 5000,
                    password: password,
                    lazyConnect: true,
                    maxRetriesPerRequest: null,
                    retryStrategy: (times) => {
                        return null;
                    },
                    autoResubscribe: false,
                    autoResendUnfulfilledCommands: false

                });
                return redis;


            default:
                throw new Error(`unknown redis type ${type}`);
        }

    }
}








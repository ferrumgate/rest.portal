import { DomainIntelligenceBWItem, DomainIntelligenceBWSource, DomainIntelligenceBWSourceEx } from "../model/domainIntelligence";
import { Util } from "../util";
import { ConfigLogService } from "./configLogService";
import { IntelligenceLogService } from "./intelligenceLogService";
import { RedisConfigService, RPathCount } from "./redisConfigService";
import { RedisPipelineService, RedisService } from "./redisService";
import { createHash } from 'node:crypto'


type Nullable<T> = T | null | undefined;

export type FqdnPath =
    'domainIntelligence/blackList' |
    'domainIntelligence/whiteList';


export class FqdnIntelligenceService {

    /**
     *
     */
    logWatcher!: IntelligenceLogService;
    /**
     * 
     * @param configService 
     * @param redis this connection must be seperate from others
     */
    constructor(protected configService: RedisConfigService, protected redis: RedisService,
        encryptKey: string,
        logWatcherWaitMS = 1000
    ) {
        this.logWatcher = new IntelligenceLogService('domainIntelligence', redis, redis.clone());

    }
    pathCalculate(path: FqdnPath) {
        return path.startsWith('/') ? `${path}` : `/${path}`
    }
    decrypt<T>(x: string) {
        /* let decrypted = Buffer.from(x, 'base64url');// x;
        if (this.configService.getEncKey()) {
            decrypted = Util.jdecrypt(this.configService.getEncKey(), decrypted);// Util.decrypt(this.getEncKey(), x, 'base64url');
        }

        return decrypted.toString(); */
        return x;

    }
    encrypt(data: string | Buffer) {
        /*  let dataStr = data;
         if (this.configService.getEncKey()) {
             dataStr = Util.jencrypt(this.configService.getEncKey(), dataStr).toString('base64url'); //Util.encrypt(this.getEncKey(), dataStr, 'base64url');
         } else
             dataStr = typeof (data) == 'string' ? Buffer.from(dataStr).toString('base64url') : dataStr;
         return dataStr; */
        return data;

        //createHash('sha512').update(data).digest('base64url')
    }

    async rGetAllBigMulti<T>(path: FqdnPath, encProbs: string[], callback?: (vals: T[]) => void) {
        const rpath = this.pathCalculate(path);

        let keys = await this.redis.getAllKeys(`${rpath}/*`);

        if (keys.length) {

            const pipe = await this.redis.multi();
            for (const k of keys) {
                await pipe.hgetAll(k);
            }
            let elements: T[] = await pipe.exec();
            elements = elements.filter((x: any) => Object.keys(x).length).map(x => {
                encProbs.forEach(y => {
                    const prob = (x as any)[y];
                    if (typeof (prob) == 'string' && prob)
                        (x as any)[y] = this.decrypt(prob);
                })
                return x;
            })
            if (callback)
                callback(elements);

            return elements;
        } else {
            if (callback)
                callback([]);

            return [];
        }

    }

    async rGetBigObj<Nullable>(path: FqdnPath, probs: string[], callback?: (val: Nullable | null) => Promise<Nullable>) {

        let rpath = this.pathCalculate(path);
        let obj = await this.redis.hgetAll(rpath) as any;
        if (obj && Object.keys(obj).length) {

            probs.forEach(y => {
                const prob = (obj as any)[y];
                if (typeof (prob) == 'string' && prob)
                    (obj as any)[y] = this.decrypt(prob);
            })
            if (callback)
                return callback(obj);
            return obj;
        } else {
            if (callback)
                return callback(null);
            return null;
        }
    }
    async rGetBigObjs<Nullable>(paths: FqdnPath[], probs: string[], callback?: (val: Nullable | null) => Promise<Nullable[]>) {

        let rpaths = paths.map(x => this.pathCalculate(x));
        const pipe = await this.redis.multi();
        for (const rpath of rpaths) {
            await pipe.hgetAll(rpath);
        }
        let objs = await pipe.exec() as any[];
        let results = [];
        for (const obj of objs) {
            if (obj) {

                probs.forEach(y => {
                    const prob = (obj as any)[y];
                    if (typeof (prob) == 'string' && prob)
                        (obj as any)[y] = this.encrypt(prob);
                })
                if (callback)
                    callback(obj);
                results.push(obj);
            }
        }
        return results;
    }

    async rGetWithBigObj<Nullable>(path: FqdnPath, id: string, probs: string[], callback?: (val: Nullable | null) => Promise<Nullable>) {
        const encStr = this.encrypt(id);
        let rpath = `${path}/${encStr}`;
        return await this.rGetBigObj(rpath as FqdnPath, probs, callback);
    }
    async rGetWithBigObjs<Nullable>(path: FqdnPath, ids: string[], probs: string[], callback?: (val: Nullable | null) => Promise<Nullable[]>) {

        let rpaths = ids.map(x => {
            const encStr = this.encrypt(x);
            let rpath = `${path}/${encStr}`;
            return rpath;
        })
        return await this.rGetBigObjs(rpaths as FqdnPath[], probs, callback);
    }

    async rDelBigObj<T>(path: FqdnPath, data: T, id: string, pipeline?: RedisPipelineService, callback?: (val: T, pipeline: RedisPipelineService) => Promise<any>) {
        if (data == null || data == undefined) return;
        let rpath = this.pathCalculate(path);
        let wrpath = this.pathCalculate(path);
        rpath += `/${this.encrypt(id)}`;
        const lpipeline = pipeline || await this.redis.multi();
        await lpipeline.remove(rpath);
        const log = { path: wrpath, type: 'del', val: data };
        await this.logWatcher.write(log, lpipeline);
        if (callback)
            callback(data, lpipeline);
        if (!pipeline)
            await lpipeline.exec();
    }
    async rSaveBigObj<T>(path: FqdnPath, id: string, probs: string[], before: T | undefined, after: T,
        pipeline?: RedisPipelineService,
        extra?: (before: T | undefined, after: T, pipeline: RedisPipelineService) => Promise<void>) {
        if (after == null || after == undefined) return;
        let rpath = this.pathCalculate(path);
        let wrpath = this.pathCalculate(path);
        rpath += `/${this.encrypt(id)}`;
        const cloned = Util.clone(after);
        probs.forEach(y => {
            const prob = (cloned as any)[y];
            if (typeof (prob) == 'string' && prob)
                (cloned as any)[y] = this.encrypt(prob);
        })


        const lpipeline = pipeline || await this.redis.multi();
        await lpipeline.hset(rpath, cloned);
        if (extra)
            await extra(before, after, lpipeline);
        const log = { path: wrpath, type: 'put', val: after, before: before }
        await this.logWatcher.write(log, lpipeline);
        if (!pipeline)
            await lpipeline.exec();

    }
    async selectBlackListDb() {
        // await this.redis.select(this.BLACKLIST_DB);
    }
    async selectWhiteListDb() {
        // await this.redis.select(this.WHITELIST_DB);
    }

    static getDomainIntelligenceBWSourceExPath(id: string) {
        return `/domainIntelligence/bwSourceEx/id/${id}`
    }
    async getDomainIntelligenceBWSourceEx(source: DomainIntelligenceBWSource, getContent = false) {
        if (!getContent) {
            const data = await this.redis.hmgetAll(FqdnIntelligenceService.getDomainIntelligenceBWSourceExPath(source.id), ['id', 'lastExecute', 'error']);
            return data as unknown as DomainIntelligenceBWSourceEx;
        }
        else {
            const data = await this.redis.hgetAll(FqdnIntelligenceService.getDomainIntelligenceBWSourceExPath(source.id));
            return data as unknown as DomainIntelligenceBWSourceEx;
        }
    }

    async saveDomainIntelligenceBWSource(source: DomainIntelligenceBWSource, fieldAndvalues: any, pipeline?: RedisPipelineService) {
        await (pipeline || this.redis).hset(FqdnIntelligenceService.getDomainIntelligenceBWSourceExPath(source.id), fieldAndvalues);
    }

    async getDomainIntelligenceBlackListBy(page: number, pageSize: number) {
        await this.selectBlackListDb();
        const key = '/domainIntelligence/index/blackList/insertDate';
        const count = '/domainIntelligence/index/blackList/count';
        const total = await this.redis.get(count, false) || 0;
        const keys = await this.redis.zrangebyscore(key, '+inf', '-inf', page * pageSize, pageSize, true);
        const items = await this.getDomainIntelligenceBlackListItems(keys);
        return { total: Number(total), items: items };
    }
    async saveDomainIntelligenceBlackListItems(items: DomainIntelligenceBWItem[]) {
        await this.selectBlackListDb();
        const pipeline = await this.redis.multi();
        let rets = [];
        for (const item of items) {
            const net = await this.rGetWithBigObj<DomainIntelligenceBWItem>('domainIntelligence/blackList', item.fqdn, ['fqdn']);
            let ret = await this.configService.createTrackEvent(net, item);
            await this.rSaveBigObj('domainIntelligence/blackList', ret.after.fqdn, ['fqdn'], ret.before, ret.after, pipeline);
            rets.push(ret);
        }
        await pipeline.exec();
        return rets;
    }

    async deleteDomainIntelligenceBlackListItems(domains: string[]) {
        await this.selectBlackListDb();
        let rets = [];
        const rules = await this.rGetWithBigObjs<DomainIntelligenceBWItem>('domainIntelligence/blackList', domains, ['fqdn']) as DomainIntelligenceBWItem[]
        if (rules.length) {

            const pipeline = await this.redis.multi();
            for (const rule of rules) {
                await this.rDelBigObj('domainIntelligence/blackList', rule, rule.fqdn, pipeline);
                let ret = this.configService.createTrackEvent(rule);
                rets.push(ret);
            }
            await pipeline.exec();

        }

        return rets.push();
    }


    async getDomainIntelligenceBlackListItems(domains: string[]) {
        await this.selectBlackListDb();
        return await this.rGetWithBigObjs<DomainIntelligenceBWItem>('domainIntelligence/blackList', domains, ['fqdn']);
    }
    async getDomainIntelligenceBlackListItem(domain: string) {
        await this.selectBlackListDb();
        return await this.rGetWithBigObj<DomainIntelligenceBWItem>('domainIntelligence/blackList', domain, ['fqdn']);
    }



    async getDomainIntelligenceWhiteListBy(page: number, pageSize: number) {
        await this.selectWhiteListDb();
        const key = '/domainIntelligence/index/whiteList/insertDate';
        const count = '/domainIntelligence/index/whiteList/count';
        const total = await this.redis.get(count, false) || 0;
        const keys = await this.redis.zrangebyscore(key, '+inf', '-inf', page * pageSize, pageSize, true);
        let items = [];
        for (const key of keys) {
            const item = await this.getDomainIntelligenceWhiteListItem(key);
            if (item)
                items.push(item);
        }
        return { total: Number(total), items: items };
    }




    async saveDomainIntelligenceWhiteListItems(items: DomainIntelligenceBWItem[]) {
        await this.selectWhiteListDb();
        const nets = await this.rGetWithBigObjs<DomainIntelligenceBWItem>('domainIntelligence/whiteList', items.map(x => x.fqdn), ['fqdn']) as DomainIntelligenceBWItem[];
        const map = new Map();
        nets.forEach(x => map.set(x.fqdn, x));

        const pipeline = await this.redis.multi();
        const rets = [];
        for (const item of items) {
            const ret = { before: map.get(item.fqdn), after: item };
            await this.rSaveBigObj('domainIntelligence/whiteList', ret.after.fqdn, ['fqdn'], ret.before, ret.after, pipeline);
            rets.push(ret);
        }

        await pipeline.exec();
        return rets;

    }

    async deleteDomainIntelligenceWhiteListItem(domain: string) {
        await this.selectWhiteListDb();
        const rule = await this.rGetWithBigObj<DomainIntelligenceBWItem>('domainIntelligence/whiteList', domain, ['fqdn']);
        if (rule) {

            const pipeline = await this.redis.multi();
            await this.rDelBigObj('domainIntelligence/whiteList', rule, rule.fqdn, pipeline);
            await pipeline.exec();

        }
        return this.configService.createTrackEvent(rule);
    }

    async getDomainIntelligenceWhiteListItem(domain: string) {
        await this.selectWhiteListDb();
        return await this.rGetWithBigObj<DomainIntelligenceBWItem>('domainIntelligence/whiteList', domain, ['fqdn']);
    }
}
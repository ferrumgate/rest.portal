import Axios, { AxiosRequestConfig } from "axios";
import { Util } from "../util";
import { Countries } from "../model/country";
import {
    IpIntelligenceItem, IpIntelligenceList,
    IpIntelligenceListFiles,
    IpIntelligenceListItem,
    IpIntelligenceListStatus, IpIntelligenceSource
} from "../model/IpIntelligence";
import { ConfigService } from "./configService";
import { RedisPipelineService, RedisService } from "./redisService";
import fsp from 'fs/promises'
import axios from "axios";
import * as fs from 'fs';
import * as stream from 'stream';
import { promisify } from 'util';
import { tmpdir } from "os";
import { createHash } from 'node:crypto'
import md5 from 'md5-file';
import { logger } from "../common";
import events from "events";
import isCidr from 'ip-cidr';
import { InputService } from "./inputService";
import IPCIDR from "ip-cidr";
import { contentSecurityPolicy } from "helmet";
import { ESService } from "./esService";

export abstract class IpIntelligenceSourceApi {

    constructor() {

    }
    abstract getType(): string;
    //abstract checkIsWorking(): Promise<any>;
    abstract query(ip: string, timeout: number): Promise<IpIntelligenceItem | null>;

}

class IPApiCom extends IpIntelligenceSourceApi {
    type: string;
    url: string;
    constructor(private apikey: string, type: string, private options: any) {
        super();
        this.type = type;
        this.url = `https://api.ipapi.com/api`;
        if (this.options.isFreePlan)
            this.url = `http://api.ipapi.com/api`;

    }
    override getType(): string {
        return this.type;
    }
    async get(ip: string, timeout = 5000) {
        let options: AxiosRequestConfig = {
            timeout: timeout,
            /* headers: {
                ApiKey: ''
            } */
        };
        const searchParams = new URLSearchParams();
        searchParams.append('access_key', this.apikey);
        if (this.options.isSecurityPlan)
            searchParams.append('security', '1');


        const url = `${this.url}/${ip}?${searchParams.toString()}`;
        const response = await Axios.get(url, options);
        const data = response.data;
        if (data.success == false)
            throw data.error;
        return data;
    }
    /* override async checkIsWorking() {

        return await this.get('1.1.1.1');
    } */
    override async query(ip: string, timeout: number) {
        const response = await this.get(ip, timeout);
        //match from our country list
        const country = Countries.find(x => x.isoCode == response.country_code);
        if (!country) return null;
        const intel: IpIntelligenceItem = {
            ip: ip,
            countryCode: country.isoCode,
            countryName: country.name,
            isCrawler: response.securiy?.is_crawler || false,
            isHosting: false,
            isProxy: response.security?.is_proxy || response.security?.is_tor || false
        }
        return intel;
    }

}



class IPDataCo extends IpIntelligenceSourceApi {
    type: string;
    url: string;
    constructor(private apikey: string, type: string, private options: any) {
        super();
        this.type = type;
        this.url = `https://api.ipdata.co`;


    }
    override getType(): string {
        return this.type;
    }
    async get(ip: string, timeout = 5000) {
        let options: AxiosRequestConfig = {
            timeout: timeout,
            /* headers: {
                ApiKey: ''
            } */
        };
        const searchParams = new URLSearchParams();
        searchParams.append('api-key', this.apikey);



        const url = `${this.url}/${ip}?${searchParams.toString()}`;
        const response = await Axios.get(url, options);
        const data = response.data;
        return data;
    }
    /* override async checkIsWorking() {

        return await this.get('1.1.1.1');
    } */
    override async query(ip: string, timeout: number) {
        const response = await this.get(ip, timeout);
        //match from our country list
        const country = Countries.find(x => x.isoCode == response.country_code);
        if (!country) return null;
        const intel: IpIntelligenceItem = {
            ip: ip,
            countryCode: country.isoCode,
            countryName: country.name,
            isCrawler: false,
            isHosting: response.threat?.is_datacenter || false,
            isProxy: response.threat?.is_proxy || response.threat?.is_tor || response.thread?.is_vpn || false
        }
        return intel;
    }

}

class IPifyOrg extends IpIntelligenceSourceApi {
    type: string;
    url: string;
    constructor(private apikey: string, type: string, private options: any) {
        super();
        this.type = type;
        this.url = `https://geo.ipify.org/api/v2/country`;
        if (options.isSecurityPlan)
            this.url = `https://geo.ipify.org/api/v2/country,city,vpn`;


    }
    override getType(): string {
        return this.type;
    }
    async get(ip: string, timeout = 5000) {
        let options: AxiosRequestConfig = {
            timeout: timeout,
            /* headers: {
                ApiKey: ''
            } */
        };
        const searchParams = new URLSearchParams();
        searchParams.append('apiKey', this.apikey);
        searchParams.append('ipAddresss', ip);


        const url = `${this.url}?${searchParams.toString()}`;
        const response = await Axios.get(url, options);
        const data = response.data;
        return data;
    }
    /* override async checkIsWorking() {

        return await this.get('1.1.1.1');
    } */
    override async query(ip: string, timeout: number) {
        const response = await this.get(ip, timeout);
        //match from our country list
        const country = Countries.find(x => x.isoCode == response.location.countryCode);
        if (!country) return null;
        const intel: IpIntelligenceItem = {
            ip: ip,
            countryCode: country.isoCode,
            countryName: country.name,
            isCrawler: false,
            isHosting: false || false,
            isProxy: response.proxy?.proxy || response.proxy?.vpn || response.proxy?.tor || false
        }
        return intel;
    }

}


export class IpIntelligenceService {
    protected api: IpIntelligenceSourceApi | null = null;
    protected apiCount = -1;
    listService!: IpIntelligenceListService;
    constructor(private config: ConfigService,
        private redisIntel: RedisService, private inputService: InputService, private esService: ESService) {
        this.listService = new IpIntelligenceListService(redisIntel, inputService, esService);
    }
    protected async createApi(force = false) {
        if (force || this.apiCount == -1) {
            await this.reConfigure();
        }

    }
    async reConfigure() {
        this.api = null;
        this.apiCount = -1;
        this.api = await this.getApi();
        if (this.api)
            this.apiCount = 1;
        else this.apiCount = 0;
    }


    protected async getApi(type?: string | IpIntelligenceSource) {
        let source: IpIntelligenceSource | undefined;
        if (typeof (type) == 'undefined' || typeof (type) == 'string') {
            let sources = (await this.config.getIpIntelligenceSources())
            if (typeof (type) == 'string')
                source = sources.find(x => x.type == type);//get correct element
            else
                source = sources.find(x => x);//find first element
            if (!source) {
                return null;
            }
        }
        else
            source = type;
        const checkType = source.type;
        switch (checkType) {
            case 'ipdata.co':
                return new IPDataCo(source.apiKey, source.type, {});
            case 'ipapi.com':
                return new IPApiCom(source.apiKey, source.type, { isFreePlan: source.isFreePlan, isSecurityPlan: source.isSecurityPlan });
            case 'ipify.org':
                return new IPifyOrg(source.apiKey, source.type, { isSecurityPlan: source.isSecurityPlan });
            default:
                throw new Error(`${type} not implemented yet`);
        }
    }

    async check(source: IpIntelligenceSource) {
        const api = await this.getApi(source);
        if (!api)
            throw new Error(`could not create an ip intelligence source for ${source.type}`);
        return await api.query('1.1.1.1', 3000);
    }

    async query(ip: string) {
        await this.createApi();
        if (Util.isLocalNetwork(ip)) return null;

        if (this.api) {
            //check from cache
            const item = await this.redisIntel.get(`/ip/intelligence/${ip}`, true);
            if (item) return item as IpIntelligenceItem;
            const result = await this.api.query(ip, 3000);
            if (result) {
                await this.redisIntel.set(`/ip/intelligence/${ip}`, result, { ttl: 6 * 60 * 60 * 1000 });//set 6 hours ttl
            }
            return result;
        }
        return null;

    }


}


export class IpIntelligenceListService {
    /**
     *
     */
    constructor(protected redisService: RedisService, protected inputService: InputService, protected esService: ESService) {

    }
    async downloadFileFromRedis(key: string, filename: string) {
        const file = await this.redisService.get(key, false) as Buffer;
        await fsp.writeFile(filename, file);
    }
    async downloadFileFromRedisH(key: string, field: string, filename: string) {
        const file = await this.redisService.hgetBuffer(key, field) as Buffer;
        await fsp.writeFile(filename, file);
    }

    async downloadFileFromUrl(url: string, filename: string) {
        await Util.downloadFile(url, filename);
    }

    async hashOfFile(filename: string) {
        return await md5(filename);
    }





    async splitFile(folder: string, filename: string, max: number) {
        let files: Map<number, { handle: fsp.FileHandle, page: number, items: string[], filepath: string }> = new Map();
        try {


            const random = Buffer.from('etriduncg7aiwriurmlheg6aroxclt1k');


            await Util.readFileLineByLine(filename, async (line) => {
                try {
                    if (line)
                        if (this.inputService.checkCidr(line, false) || this.inputService.checkIp(line, false)) {
                            const hash = Util.fastHashLow(line, random);
                            const file = hash % max;
                            const filepath = `${folder}/${file}_file`;
                            if (!files.has(file)) {
                                const fileHandle = await fsp.open(filepath, 'w+');//truncate and open
                                files.set(file, { handle: fileHandle, page: file, items: [], filepath: filepath });
                            }
                            const model = files.get(file);
                            model?.items.push(line);
                            if (model && model.items.length > 10000) {
                                await model.handle.write(model.items.join('\n') + '\n');
                                model.items = [];
                            }
                        }
                } catch (ignore) {

                }
                return true;
            });
            for (const opened of files) {
                if (opened[1].items.length)
                    await opened[1].handle.write(opened[1].items.join('\n') + '\n');
            }
            let retItems = [];
            for (const f of files) {
                retItems.push({ filename: f[1].filepath, page: f[1].page, hash: await this.hashOfFile(f[1].filepath) });
            }
            return retItems;
        } finally {
            for (const opened of files) {
                try {
                    await opened[1].handle.close();
                } catch (ignore) { }
            }
        }

    }
    async getListStatus(item: IpIntelligenceList): Promise<IpIntelligenceListStatus | null> {

        const val = (await this.redisService.get(`/intelligence/ip/list/${item.id}/status`, true));
        return val as any;
    }
    async getListStatusBulk(items: IpIntelligenceList[]): Promise<IpIntelligenceListStatus[]> {
        if (!items.length) return [];
        const pipeline = await this.redisService.pipeline();
        for (const item of items) {
            await pipeline.get(`/intelligence/ip/list/${item.id}/status`, false);
        }
        const results = await pipeline.exec() as string[];
        return results.filter(x => x).map(x => JSON.parse(x));
    }

    async saveListStatus(item: IpIntelligenceList, status: IpIntelligenceListStatus, pipeline?: RedisPipelineService) {
        return await (this.redisService || pipeline).set(`/intelligence/ip/list/${item.id}/status`, status);
    }
    async deleteListStatus(item: IpIntelligenceList, pipeline?: RedisPipelineService) {
        return await (this.redisService || pipeline).delete(`/intelligence/ip/list/${item.id}/status`);
    }


    async getDbFileList(item: IpIntelligenceList): Promise<IpIntelligenceListFiles | null> {
        const items = await this.redisService.hgetAll(`/intelligence/ip/list/${item.id}/files`) as any;
        Object.keys(items).forEach(y => {
            items[y] = JSON.parse(items[y])
        })
        return items as IpIntelligenceListFiles;
    }
    async saveDbFileList(item: IpIntelligenceList, files: IpIntelligenceListFiles, pipeline?: RedisPipelineService) {
        const cloned = JSON.parse(JSON.stringify(files));
        Object.keys(cloned).forEach(y => {
            cloned[y] = JSON.stringify(cloned[y]);
        })
        return await (this.redisService || pipeline).hset(`/intelligence/ip/list/${item.id}/files`, cloned);
    }
    async deleteDbFileList(item: IpIntelligenceList, pipeline?: RedisPipelineService) {
        return await (this.redisService || pipeline).delete(`/intelligence/ip/list/${item.id}/files`);
    }
    async deleteDbFileList2(item: IpIntelligenceList, page: number, pipeline?: RedisPipelineService) {
        return await (this.redisService || pipeline).hdel(`/intelligence/ip/list/${item.id}/files`, [page.toString()]);
    }
    async saveListFile(item: IpIntelligenceList, filename: string, pipeline?: RedisPipelineService) {
        const key = `/intelligence/ip/list/${item.id}/file`;
        const multi = pipeline || await this.redisService.multi();
        const buffer = await fsp.readFile(filename, { encoding: 'binary' });
        await multi.hset(key, { content: buffer });
        if (!pipeline)
            await multi.exec();
    }

    async deleteListFile(item: IpIntelligenceList, pipeline?: RedisPipelineService) {
        const key = `/intelligence/ip/list/${item.id}/file`;
        const multi = pipeline || await this.redisService.multi();
        await multi.delete(key);
        if (!pipeline)
            await multi.exec();
    }

    async deleteFromStore(item: IpIntelligenceList, page?: number) {
        await this.esService.deleteIpIntelligenceList({ id: item.id, page: page });

    }

    async compareSystemHealth(items: IpIntelligenceList[]) {
        const keys = await this.redisService.getAllKeys('/intelligence/ip/list/*');
        const itemIds = items.map(x => x.id.toLowerCase());
        const pipe = await this.redisService.pipeline();//we did it pipeline,not multi
        for (const it of keys) {
            const ids = it.replace('/intelligence/ip/list/', '').split('/')
            const id = ids[0];
            if (id) {
                if (!itemIds.includes(id)) {
                    await pipe.delete(it);
                }
            }
        }
        await pipe.exec();
    }



    async saveToStore(item: IpIntelligenceList, file: string, page: number) {

        let items: [IpIntelligenceListItem, string][] = [];
        await Util.readFileLineByLine(file, async (line: string) => {

            if (!line.includes('/'))//must be cidr
                if (line.includes(":"))
                    line += '/128';
                else
                    line += '/32';
            const cidr = new IPCIDR(line);
            let val: IpIntelligenceListItem =
                { id: item.id, insertDate: new Date().toISOString(), network: cidr.toString(), page: page };


            const tmp = await this.esService.ipIntelligenceListCreateIndexIfNotExits(val)
            items.push(tmp);
            if (items.length >= 1000) {
                await this.esService.ipIntelligenceListItemSave(items);
                items = [];
            }
            return true;
        })
        if (items.length) {
            await this.esService.ipIntelligenceListItemSave(items);
            items = [];
        }
    }

    /**
     * search in listId
     * @param ip 
     * @returns first founded list id
     */
    async getByIp(listId: string, ip: string) {
        const items = await this.esService.searchIpIntelligenceList({ searchIp: ip, id: listId });
        return items.items.length ? items.items[0] : null;

    }
    /**
     * search in all lists
     * @param ip 
     * @returns first founded list id
     */
    async getByIpAll(ip: string) {
        return await this.esService.searchIpIntelligenceList({ searchIp: ip });

    }

    async deleteList(item: IpIntelligenceList) {
        //we need to get all  pages of list first

        const trx = await this.redisService.multi();
        await this.deleteDbFileList(item, trx);
        await this.deleteListStatus(item, trx);
        await this.deleteListFile(item, trx);
        await trx.exec();
        await this.deleteFromStore(item);
    }

    /**
     * we wrote for support downloading files
     * @param item 
     * @param cont 
     * @param callback 
     * @returns 
     */
    async getAllListItems(item: IpIntelligenceList, cont: () => boolean, callback?: (item: string) => Promise<void>) {
        let items: string[] = [];
        await this.esService.scrollIpIntelligenceList({ id: item.id }, cont, async (val: IpIntelligenceListItem) => {
            if (callback)
                await callback(val.network);
            else items.push(val.network);
        })
        return items;

    }
    async resetList(item: IpIntelligenceList) {
        let status = await this.getListStatus(item);
        if (!status) {
            status = {
                id: item.id
            }
        }
        status.hash = '';
        status.lastError = 'reset';
        status.lastCheck = new Date().toISOString()
        await this.deleteFromStore(item);
        const trx = await this.redisService.multi();
        await this.saveListStatus(item, status, trx);
        await this.deleteListStatus(item, trx);
        await this.deleteDbFileList(item, trx);
        await trx.exec();

    }


    async process(item: IpIntelligenceList) {
        logger.info(`ip intelligence processing item ${item.name}`);
        if (!item.http && !item.file) return;//no file


        let status: IpIntelligenceListStatus | null = null;
        const tmpDirectory = `/tmp/${Util.randomNumberString()}`;

        try {
            status = await this.getListStatus(item);
            await fsp.mkdir(tmpDirectory, { recursive: true });
            const tmpFilename = `${tmpDirectory}/${Util.randomNumberString()}`
            let hash = '';
            if (item.http) {
                logger.info(`ip intelligence downloading ${item.name} data from ${item.http.url}`);
                await this.downloadFileFromUrl(item.http.url, tmpFilename);
                hash = status?.hash || '';

            } else
                if (item.file) {
                    logger.info(`ip intelligence downloading ${item.name} data from file`);
                    const key = `/intelligence/ip/list/${item.id}/file`;
                    await this.downloadFileFromRedisH(key, 'content', tmpFilename);
                    hash = status?.hash || '';
                }
            const fileHash = await this.hashOfFile(tmpFilename);
            let isChanged = false;
            let hasFile = false;
            if (hash != fileHash) {
                hash = fileHash;
                logger.info(`ip intelligence splitting file ${tmpFilename}`)
                const files = await this.splitFile(tmpDirectory, tmpFilename, 10000);
                hasFile = files.length > 0;
                // make map for fast iteration
                const filesMap: Map<number, { page: number, hash: string, filename: string }> = new Map();
                for (const file of files) {
                    filesMap.set(file.page, file);
                }


                const dbFiles = await this.getDbFileList(item) || {};
                //make map for fast iteration
                const dbFilesMap: Map<number, { page: number, hash: string }> = new Map();
                Object.keys(dbFiles).forEach(y => {
                    dbFilesMap.set(Number(y), dbFiles[y]);
                })


                //compare each other
                for (const iterator of dbFilesMap.values()) {
                    if (!filesMap.has(iterator.page)) {//delete this from database
                        logger.info(`ip intelligence ${item.name} deleting page:${iterator.page}`)

                        await this.deleteFromStore(item, iterator.page);
                        const multi = await this.redisService.multi();
                        await this.deleteDbFileList2(item, iterator.page, multi);
                        await multi.exec();
                        isChanged = true;
                    }
                }

                for (const iterator of filesMap.values()) {//save or update
                    //delete this from database first, because hash changed of file
                    if (dbFilesMap.has(iterator.page)) {
                        if (dbFilesMap.get(iterator.page)?.hash != iterator.hash) {
                            logger.info(`ip intelligence ${item.name} updating page:${iterator.page}`);

                            await this.deleteFromStore(item, iterator.page);
                            const multi = await this.redisService.multi();
                            await this.deleteDbFileList2(item, iterator.page, multi);
                            await multi.exec();

                            const multi2 = await this.redisService.multi();
                            await this.saveToStore(item, iterator.filename, iterator.page);
                            const savelist: IpIntelligenceListFiles = {};
                            savelist[iterator.page] = { hash: iterator.hash, page: iterator.page };
                            await this.saveDbFileList(item, savelist);
                            await multi2.exec();
                            isChanged = true;
                        }
                    } else {
                        logger.info(`ip intelligence ${item.name} saving page:${iterator.page}`)
                        const multi2 = await this.redisService.multi();
                        await this.saveToStore(item, iterator.filename, iterator.page);
                        const savelist: IpIntelligenceListFiles = {};
                        savelist[iterator.page] = { hash: iterator.hash, page: iterator.page };
                        await this.saveDbFileList(item, savelist);
                        await multi2.exec();
                        isChanged = true;
                    }
                }
            } else {
                logger.info(`ip intelligence ${item.name} file not changed`);
            }


            let saveStatus: IpIntelligenceListStatus = {
                id: item.id,
                hash: hash,
                lastCheck: new Date().toISOString(),
                lastError: '',
                isChanged: isChanged,
                hasFile: hasFile
            }
            await this.saveListStatus(item, saveStatus);



        } catch (err: any) {
            let saveStatus: IpIntelligenceListStatus = {
                id: item.id,
                hash: status?.hash || '',
                lastCheck: new Date().toISOString(),
                lastError: err.message,
                isChanged: false,
                hasFile: status?.hasFile
            }
            try {
                await this.saveListStatus(item, saveStatus);
            } catch (ignore) { }
            throw err;
        }

        finally {
            try {
                await fsp.rm(tmpDirectory, { recursive: true, force: true });
            } catch (ignore) { }
        }

    }





}
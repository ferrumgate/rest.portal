import Axios, { AxiosRequestConfig } from "axios";
import { Util } from "../util";
import { Countries } from "../model/country";
import {
    FqdnIntelligenceItem, FqdnIntelligenceList,
    FqdnIntelligenceListFiles,
    FqdnIntelligenceListItem,
    FqdnIntelligenceListStatus, FqdnIntelligenceSource
} from "../model/fqdnIntelligence";
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
import isFQDN from "validator/lib/isFQDN";

export abstract class FqdnIntelligenceSourceService {

    constructor() {

    }
    abstract getType(): string;
    //abstract checkIsWorking(): Promise<any>;
    abstract query(fqdn: string, timeout: number): Promise<FqdnIntelligenceItem | null>;

}



export class FqdnIntelligenceService {
    protected service: FqdnIntelligenceSourceService | null = null;
    protected serviceCount = -1;
    listService!: FqdnIntelligenceListService;
    constructor(private config: ConfigService,
        private redisIntel: RedisService, private inputService: InputService, private esService: ESService) {
        this.listService = new FqdnIntelligenceListService(redisIntel, inputService, esService);
    }
    protected async createService(force = false) {
        if (force || this.serviceCount == -1) {
            await this.reConfigure();
        }

    }
    async reConfigure() {
        this.service = null;
        this.serviceCount = -1;
        this.service = await this.getService();
        if (this.service)
            this.serviceCount = 1;
        else this.serviceCount = 0;
    }


    protected async getService(type?: string | FqdnIntelligenceSource): Promise<FqdnIntelligenceSourceService> {

        throw new Error(`${type} not implemented yet`);

    }

    async check(source: FqdnIntelligenceSource) {
        const service = await this.getService(source);
        //  if (!service)
        throw new Error(`could not create an fqdn intelligence source for ${source.type}`);
        //  return await service.query('ferrumgate.com', 3000);
    }

    async query(fqdn: string) {
        await this.createService();


        if (this.service) {
            //check from cache
            const item = await this.redisIntel.get(`/fqdn/intelligence/${fqdn}`, true);
            if (item) return item as FqdnIntelligenceItem;
            const result = await this.service.query(fqdn, 3000);
            if (result) {
                await this.redisIntel.set(`/fqdn/intelligence/${fqdn}`, result, { ttl: 6 * 60 * 60 * 1000 });//set 6 hours ttl
            }
            return result;
        }
        return null;

    }


}


export class FqdnIntelligenceListService {
    /**
     *
     */
    constructor(protected redisService: RedisService, protected inputService: InputService, protected esService: ESService) {

    }
    /* async downloadFileFromRedis(key: string, filename: string) {
        const file = await this.redisService.get(key, false) as Buffer;
        await fsp.writeFile(filename, file);
    } */
    async prepareFile(originalFilename: string, filename: string, baseDirectory: string) {
        const nextDir = `${baseDirectory}/${Util.randomNumberString(16)}`
        await fsp.mkdir(nextDir);
        if (originalFilename.endsWith('.zip')) {
            logger.info(`extracting zip file`);
            await Util.extractZipFile(filename, nextDir);
            //find all files
            const files = await Util.listAllFiles(nextDir);
            await fsp.unlink(filename);
            // and merge them
            await Util.mergeAllFiles(files.sort((a, b) => a.localeCompare(b)), filename);
        } else
            if (originalFilename.endsWith('.tar.gz')) {
                logger.info(`extracting zip file`);
                await Util.extractTarGz(filename, nextDir);
                //find all files
                const files = await Util.listAllFiles(nextDir);
                await fsp.unlink(filename);
                // and merge them
                await Util.mergeAllFiles(files.sort((a, b) => a.localeCompare(b)), filename);
            }
    }
    async downloadFileFromRedisH(key: string, field: string, filename: string, originalFileName: string, baseDirectory: string) {
        const file = await this.redisService.hgetBuffer(key, field) as Buffer;
        await fsp.writeFile(filename, file);
        await this.prepareFile(originalFileName, filename, baseDirectory);
    }

    async downloadFileFromUrl(url: string, baseDirectory: string, filename: string) {
        await Util.downloadFile(url, filename);
        await this.prepareFile(url, filename, baseDirectory);


    }

    async hashOfFile(filename: string) {
        return await md5(filename);
    }





    async splitFile(folder: string, filename: string, max: number, splitter?: string, splitterIndex?: number) {
        let files: Map<number, { handle: fsp.FileHandle, page: number, items: string[], filepath: string }> = new Map();
        try {


            const random = Buffer.from('xn4ifdqqyvgs7vs5kifrb2jkrwawn1z5');


            await Util.readFileLineByLine(filename, async (line) => {
                try {
                    if (line) {
                        if (splitter) {//split line
                            const parts = line.split(splitter);
                            line = splitterIndex ? parts[splitterIndex] : parts[0];
                            if (line)
                                line = line.replace(/"/g, '').replace(/'/g, '').trim();
                        } else
                            line = line.trim();
                        if (line && !line.startsWith('#')) {
                            line = line.replace(/^\*+/, '').replace(/\*$/, '');
                            line = line.replace(/^\.+/, '').replace(/\.$/, '');
                            line = line.trim();
                            const isfqdn = isFQDN(line, { require_tld: false });
                            if (isfqdn) {
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
    async getListStatus(item: FqdnIntelligenceList): Promise<FqdnIntelligenceListStatus | null> {

        const val = (await this.redisService.get(`/intelligence/fqdn/list/${item.id}/status`, true));
        return val as any;
    }
    async getListStatusBulk(items: FqdnIntelligenceList[]): Promise<FqdnIntelligenceListStatus[]> {
        if (!items.length) return [];
        const pipeline = await this.redisService.pipeline();
        for (const item of items) {
            await pipeline.get(`/intelligence/fqdn/list/${item.id}/status`, false);
        }
        const results = await pipeline.exec() as string[];
        return results.filter(x => x).map(x => JSON.parse(x));
    }

    async saveListStatus(item: FqdnIntelligenceList, status: FqdnIntelligenceListStatus, pipeline?: RedisPipelineService) {
        return await (this.redisService || pipeline).set(`/intelligence/fqdn/list/${item.id}/status`, status);
    }
    async deleteListStatus(item: FqdnIntelligenceList, pipeline?: RedisPipelineService) {
        return await (this.redisService || pipeline).delete(`/intelligence/fqdn/list/${item.id}/status`);
    }


    async getDbFileList(item: FqdnIntelligenceList): Promise<FqdnIntelligenceListFiles | null> {
        const items = await this.redisService.hgetAll(`/intelligence/fqdn/list/${item.id}/files`) as any;
        Object.keys(items).forEach(y => {
            items[y] = JSON.parse(items[y])
        })
        return items as FqdnIntelligenceListFiles;
    }
    async saveDbFileList(item: FqdnIntelligenceList, files: FqdnIntelligenceListFiles, pipeline?: RedisPipelineService) {
        const cloned = JSON.parse(JSON.stringify(files));
        Object.keys(cloned).forEach(y => {
            cloned[y] = JSON.stringify(cloned[y]);
        })
        return await (this.redisService || pipeline).hset(`/intelligence/fqdn/list/${item.id}/files`, cloned);
    }
    async deleteDbFileList(item: FqdnIntelligenceList, pipeline?: RedisPipelineService) {
        return await (this.redisService || pipeline).delete(`/intelligence/fqdn/list/${item.id}/files`);
    }
    async deleteDbFileList2(item: FqdnIntelligenceList, page: number, pipeline?: RedisPipelineService) {
        return await (this.redisService || pipeline).hdel(`/intelligence/fqdn/list/${item.id}/files`, [page.toString()]);
    }
    async saveListFile(item: FqdnIntelligenceList, filename: string, pipeline?: RedisPipelineService) {
        const key = `/intelligence/fqdn/list/${item.id}/file`;
        const multi = pipeline || await this.redisService.multi();
        const buffer = await fsp.readFile(filename, { encoding: 'binary' });
        await multi.hset(key, { content: buffer });
        if (!pipeline)
            await multi.exec();
    }

    async deleteListFile(item: FqdnIntelligenceList, pipeline?: RedisPipelineService) {
        const key = `/intelligence/fqdn/list/${item.id}/file`;
        const multi = pipeline || await this.redisService.multi();
        await multi.delete(key);
        if (!pipeline)
            await multi.exec();
    }

    async deleteFromStore(item: FqdnIntelligenceList, page?: number) {
        await this.esService.deleteFqdnIntelligenceList({ id: item.id, page: page });

    }

    async compareSystemHealth(items: FqdnIntelligenceList[]) {
        const keys = await this.redisService.getAllKeys('/intelligence/fqdn/list/*');
        const itemIds = items.map(x => x.id);
        const pipe = await this.redisService.pipeline();//we did it pipeline,not multi
        for (const it of keys) {
            const ids = it.replace('/intelligence/fqdn/list/', '').split('/')
            const id = ids[0];
            if (id) {
                if (!itemIds.includes(id)) {
                    await pipe.delete(it);
                }
            }
        }
        await pipe.exec();
    }



    async saveToStore(item: FqdnIntelligenceList, file: string, page: number) {

        let items: [FqdnIntelligenceListItem, string][] = [];
        await Util.readFileLineByLine(file, async (line: string) => {
            if (line.startsWith('#'))
                return true;

            line = line.replace(/^\*+/, '').replace(/\*$/, '');
            line = line.replace(/^\.+/, '').replace(/\.$/, '');

            const isfqdn = isFQDN(line, { require_tld: false });
            if (isfqdn) {
                let val: FqdnIntelligenceListItem =
                    { id: item.id, insertDate: new Date().toISOString(), fqdn: line.toString(), page: page };


                const tmp = await this.esService.fqdnIntelligenceListCreateIndexIfNotExits(val)
                items.push(tmp);
                if (items.length >= 1000) {
                    await this.esService.fqdnIntelligenceListItemSave(items);
                    items = [];
                }
            }
            return true;
        })
        if (items.length) {
            await this.esService.fqdnIntelligenceListItemSave(items);
            items = [];
        }
    }

    /**
     * search in listId
     * @param ip 
     * @returns first founded list id
     */
    async getByFqdn(listId: string, fqdn: string) {
        const items = await this.esService.searchFqdnIntelligenceList({ searchFqdn: fqdn, id: listId });
        return items.items.length ? items.items[0] : null;

    }
    /**
     * search in all lists
     * @param ip 
     * @returns first founded list id
     */
    async getByFqdnAll(fqdn: string) {
        return await this.esService.searchFqdnIntelligenceList({ searchFqdn: fqdn });

    }

    async deleteList(item: FqdnIntelligenceList) {
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
    async getAllListItems(item: FqdnIntelligenceList, cont: () => boolean, callback?: (item: string) => Promise<void>) {
        let items: string[] = [];
        await this.esService.scrollFqdnIntelligenceList({ id: item.id }, cont, async (val: FqdnIntelligenceListItem) => {
            if (callback)
                await callback(val.fqdn);
            else items.push(val.fqdn);
        })
        return items;

    }
    async resetList(item: FqdnIntelligenceList) {
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


    async process(item: FqdnIntelligenceList) {
        logger.info(`fqdn intelligence processing item ${item.name}`);
        if (!item.http && !item.file) return;//no file


        let status: FqdnIntelligenceListStatus | null = null;
        const tmpDirectory = `/tmp/${Util.randomNumberString(16)}`;

        try {
            status = await this.getListStatus(item);
            await fsp.mkdir(tmpDirectory, { recursive: true });
            const tmpFilename = `${tmpDirectory}/${Util.randomNumberString(16)}`
            let hash = '';
            if (item.http) {
                logger.info(`fqdn intelligence downloading ${item.name} data from ${item.http.url}`);
                await this.downloadFileFromUrl(item.http.url, tmpDirectory, tmpFilename);
                hash = status?.hash || '';

            } else
                if (item.file) {
                    logger.info(`fqdn intelligence downloading ${item.name} data from file`);
                    const key = `/intelligence/fqdn/list/${item.id}/file`;
                    await this.downloadFileFromRedisH(key, 'content', tmpFilename, item.file.source || '', tmpDirectory);
                    hash = status?.hash || '';
                }
            const fileHash = await this.hashOfFile(tmpFilename);
            let isChanged = false;
            let hasFile = false;
            if (hash != fileHash) {
                hash = fileHash;
                logger.info(`fqdn intelligence splitting file ${tmpFilename}`)
                const files = await this.splitFile(tmpDirectory, tmpFilename, 10000, item.splitter, item.splitterIndex);
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
                        logger.info(`fqdn intelligence ${item.name} deleting page:${iterator.page}`)

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
                            logger.info(`fqdn intelligence ${item.name} updating page:${iterator.page}`);

                            await this.deleteFromStore(item, iterator.page);
                            const multi = await this.redisService.multi();
                            await this.deleteDbFileList2(item, iterator.page, multi);
                            await multi.exec();

                            const multi2 = await this.redisService.multi();
                            await this.saveToStore(item, iterator.filename, iterator.page);
                            const savelist: FqdnIntelligenceListFiles = {};
                            savelist[iterator.page] = { hash: iterator.hash, page: iterator.page };
                            await this.saveDbFileList(item, savelist);
                            await multi2.exec();
                            isChanged = true;
                        }
                    } else {
                        logger.info(`fqdn intelligence ${item.name} saving page:${iterator.page}`)
                        const multi2 = await this.redisService.multi();
                        await this.saveToStore(item, iterator.filename, iterator.page);
                        const savelist: FqdnIntelligenceListFiles = {};
                        savelist[iterator.page] = { hash: iterator.hash, page: iterator.page };
                        await this.saveDbFileList(item, savelist);
                        await multi2.exec();
                        isChanged = true;
                    }
                }
            } else {
                logger.info(`fqdn intelligence ${item.name} file not changed`);
            }


            let saveStatus: FqdnIntelligenceListStatus = {
                id: item.id,
                hash: hash,
                lastCheck: new Date().toISOString(),
                lastError: '',
                isChanged: isChanged,
                hasFile: hasFile
            }
            await this.saveListStatus(item, saveStatus);



        } catch (err: any) {
            let saveStatus: FqdnIntelligenceListStatus = {
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
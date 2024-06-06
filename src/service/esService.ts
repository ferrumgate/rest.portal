import * as ES from '@elastic/elasticsearch';
import { ActivityLog } from '../model/activityLog';
import { Util } from '../util';
import fsp from 'fs/promises';
import { logger } from '../common';
import { AuditLog } from '../model/auditLog';
import { ConfigWatch } from '../model/config';
import { DeviceLog } from '../model/device';
import { FqdnIntelligenceListItem } from '../model/fqdnIntelligence';
import { IpIntelligenceListItem } from '../model/ipIntelligence';
import { ConfigService } from './configService';

const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');
const ThreeMinutes = 3 * 60 * 1000;


export interface ESAuditLog extends AuditLog {

}

export interface ESActivityLog extends ActivityLog {

}

export interface ESDeviceLog extends DeviceLog {

}
export interface SearchAuditLogsRequest {
    startDate?: string;
    endDate?: string;
    search?: string;
    username?: string;
    message?: string;
    page?: number;
    pageSize?: number;
}

export interface SearchActivityLogsRequest {
    startDate?: string;
    endDate?: string;
    search?: string;
    page?: number;
    pageSize?: number;

    requestId?: string;
    type?: string;//'login try','login allow','login deny','service allow','service deny','pam activated'
    authSource?: string;//google, apikey
    ip?: string;
    status?: number;//0 success;
    statusMessage?: string;
    statusMessageDetail?: string;



    username?: string;
    userId?: string;
    user2FA?: boolean;


    sessionId?: string;
    is2FA?: boolean;

    trackId?: number;
    assignedIp?: string;
    tunnelId?: string;
    serviceId?: string;
    serviceName?: string;
    networkId?: string;
    networkName?: string;
    gatewayId?: string;
    gatewayName?: string;
    tun?: string;
    authnRuleId?: string
    authnRuleName?: string;
    authzRuleId?: string;
    authzRuleName?: string;

    deviceId?: string;
    deviceName?: string;
    osName?: string;
    osVersion?: string;
    osPlatform?: string;
    browser?: string;
    browserVersion?: string;
    requestPath?: string;

    sourceIp?: string;
    sourcePort?: number;
    destinationIp?: string;
    destinationPort?: number;
    networkProtocol?: string;
}

export interface SearchDeviceLogsRequest {
    startDate?: string;
    endDate?: string;
    search?: string;
    page?: number;
    id?: string;
    userId?: string;
    username?: string;
    isHealthy?: boolean;
    hostname?: string;
    pageSize?: number;
}

export interface SearchSummaryRequest {
    startDate?: string;
    endDate?: string;
    timeZone?: string;

}
export interface SearchSummaryUserRequest extends SearchSummaryRequest {
    username: string;
}

/**
 * @summary elastic search aggregeation
 */
export interface ESAgg {
    total: number;
    aggs: ESAggItem[];
}
export interface ESAggItem {
    key: any,
    value: number;
    sub?: ESAggItem[]

}

// ip intelligence
export interface ESIpIntelligenceListItem extends IpIntelligenceListItem {

}

export interface SearchIpIntelligenceListRequest {
    id?: string;
    searchIp: string;

}

export interface DeleteIpIntelligenceListRequest {
    id: string;
    page?: number;
}
export interface ScrollIpIntelligenceListRequest {
    id: string;
}

// fqdn intelligence

export interface ESFqdnIntelligenceListItem extends FqdnIntelligenceListItem {

}
export interface SearchFqdnIntelligenceListRequest {
    id?: string;
    searchFqdn: string;

}

export interface DeleteFqdnIntelligenceListRequest {
    id: string;
    page?: number;
}
export interface ScrollFqdnIntelligenceListRequest {
    id: string;
}

/**
 * @summary elastic service
 */
export class ESService {

    private auditIndexes: Map<string, number> = new Map<string, number>();
    private activityIndexes: Map<string, number> = new Map<string, number>();
    private deviceIndexes: Map<string, number> = new Map<string, number>();
    private ipIntelligenceListIndexes: Map<string, number> = new Map<string, number>();
    private fqdnIntelligenceListIndexes: Map<string, number> = new Map<string, number>();
    private client!: ES.Client;
    host?: string;
    username?: string;
    password?: string;
    /**
     *  
     */
    constructor(configService: ConfigService, host?: string, username?: string, password?: string, private refreshInterval = '60s') {
        this.host = host;
        this.username = username;
        this.password = password;
    }

    async createClient(force = false) {
        if (!force && this.client) return;
        try {
            if (this.client)
                await this.client.close();
        } catch (ignore) {
            logger.error(ignore);
        }

        let option: ES.ClientOptions = {
            node: this.host || 'https://localhost:9200', auth: {
                username: this.username || '',
                password: this.password || ''
            },
            tls: { rejectUnauthorized: false },

        }
        this.auditIndexes = new Map<string, number>();
        this.activityIndexes = new Map<string, number>();
        this.ipIntelligenceListIndexes = new Map<string, number>();
        this.fqdnIntelligenceListIndexes = new Map<string, number>();
        this.client = new ES.Client(option);

    }
    async reConfigure(host: string, username?: string, password?: string, refresh_interval?: string) {
        try {
            if (refresh_interval)
                this.refreshInterval = refresh_interval;
            if (this.host != host || this.username != username || this.password != password) {
                logger.info(`reconfigure es to host: ${host}`);
                this.host = host;
                this.username = username;
                this.password = password;
                await this.createClient(true);
                //try create some indexes
                try {
                    await this.auditCreateIndexIfNotExits({} as any);
                } catch (err) { logger.error(err); }
            }


        } catch (err) {
            logger.error(err);
        }
    }
    getIndexName(index: string) {

        let ferrumCloudId = process.env.FERRUM_CLOUD_ID;
        if (ferrumCloudId && !index.startsWith(`${ferrumCloudId}-`))
            return `${ferrumCloudId}-${index}`;
        return index;
    }


    async search(request: any): Promise<any> {
        await this.createClient();
        request.ignore_unavailable = true;
        return await this.client.search(request);

    }
    async getAllIndexes() {
        await this.createClient();
        const indexes = await this.client.cat.indices({ format: 'json', index: this.getIndexName('*') });
        return indexes.filter(x => x.index).map(x => x.index) as string[];
    }
    async reset() {
        await this.createClient();
        const allIndexes = await this.getAllIndexes();
        if (allIndexes.length)
            await this.client.indices.delete({ index: allIndexes })

    }
    async deleteIndexes(indexes: string[]) {
        const preparedIndexes = indexes.map(x => this.getIndexName(x) || x);
        await this.client.indices.delete({ index: preparedIndexes, ignore_unavailable: true })
    }

    async flush(index?: string) {
        await this.createClient();
        await this.client.indices.flush({
            index: index ? this.getIndexName(index) : index,
            force: true
        });
    }


    ////audit 
    async auditCreateIndexIfNotExits(item: AuditLog): Promise<[ESAuditLog, string]> {
        await this.createClient();
        let index = this.getIndexName('ferrumgate-audit');
        let esitem: ESAuditLog =
        {
            ...item

        };
        const foundedIndex = this.auditIndexes.get(index);
        if ((foundedIndex || 0) > new Date().getTime()) return [esitem, index];

        let exists = (await this.client.indices.exists({ index: index }));
        if (!exists) {


            await this.client.indices.create({
                index: index,
                body: {
                    settings: {
                        index: {
                            number_of_replicas: Number(process.env.ES_REPLICAS) || 2,
                            number_of_shards: Number(process.env.ES_SHARDS) || 1,
                            "refresh_interval": this.refreshInterval,
                            translog: {
                                "durability": "async",
                                "sync_interval": "10s",
                                "flush_threshold_size": "1gb"
                            }


                        }
                    },
                    mappings: {


                        properties: {
                            insertDate: {
                                type: 'date', // type is a required attribute if index is specified

                            },

                            userId: {
                                type: "keyword"

                            },
                            username: {
                                type: "keyword"

                            },
                            message: {
                                type: "keyword"

                            },
                            messageSummary: {
                                type: "keyword"

                            },
                            messageDetail: {
                                type: "text"

                            },
                            ip: {
                                type: "keyword",
                                fields: {
                                    addr: {
                                        type: 'ip'
                                    }
                                }

                            },
                            severity: {
                                type: "keyword"

                            },
                            tags: {
                                type: "keyword"

                            },
                        }

                    }
                }
            })


        }
        this.auditIndexes.set(index, new Date().getTime() + ThreeMinutes);
        return [esitem, index];
    }



    async auditSave(items: [ESAuditLog, string][]): Promise<void> {
        await this.createClient();
        let indexList = new Set<string>();
        items.forEach(x => {
            indexList.add(x[1]);
        });
        indexList.forEach(async x => {
            let result: any[] = [];
            let mapped = items.filter(y => y[1] == x).map(doc => [{ index: { _index: this.getIndexName(doc[1]) } }, doc[0]])
            mapped.forEach(x => {
                result = result.concat(x);
            });
            await this.client.bulk({
                index: this.getIndexName(x),
                body: result
            })
        });
    }


    ////ip intelligence list 
    async ipIntelligenceListCreateIndexIfNotExits(item: IpIntelligenceListItem): Promise<[ESIpIntelligenceListItem, string]> {
        await this.createClient();

        let index = this.getIndexName(`ip-intelligence-list-${item.id.toLowerCase()}`);
        let esitem: ESIpIntelligenceListItem =
        {
            ...item

        };
        const foundedIndex = this.ipIntelligenceListIndexes.get(index);
        if ((foundedIndex || 0) > new Date().getTime()) return [esitem, index];

        let exists = (await this.client.indices.exists({ index: index }));
        if (!exists) {


            await this.client.indices.create({
                index: index,
                body: {
                    settings: {
                        index: {
                            number_of_replicas: 1,
                            number_of_shards: 1,
                            "refresh_interval": this.refreshInterval,
                            translog: {
                                "durability": "async",
                                "sync_interval": "10s",
                                "flush_threshold_size": "1gb"
                            }
                        }
                    },
                    mappings: {

                        properties: {
                            insertDate: {
                                type: 'date', // type is a required attribute if index is specified

                            },

                            id: {
                                type: "keyword"

                            },

                            page: {
                                type: "integer"

                            },
                            network: {
                                type: "ip_range",
                                fields: {
                                    value: {
                                        "type": "keyword"
                                    }
                                }


                            }
                        }

                    }
                }
            })


        }
        this.ipIntelligenceListIndexes.set(index, new Date().getTime() + ThreeMinutes);
        return [esitem, index];
    }

    async ipIntelligenceListItemSave(items: [ESIpIntelligenceListItem, string][]): Promise<void> {
        await this.createClient();
        let indexList = new Set<string>();
        items.forEach(x => {
            indexList.add(x[1]);
        });
        indexList.forEach(async x => {
            let result: any[] = [];
            let mapped = items.filter(y => y[1] == x).map(doc => [{ index: { _index: this.getIndexName(doc[1]) } }, doc[0]])
            mapped.forEach(x => {
                result = result.concat(x);
            });
            await this.client.bulk({
                index: this.getIndexName(x),
                body: result
            })
        });
    }

    async searchIpIntelligenceList(req: SearchIpIntelligenceListRequest) {
        await this.createClient();
        let request = {
            ignore_unavailable: true,
            index: this.getIndexName(`ip-intelligence-list-${req.id ? req.id.toLowerCase() : '*'}`),
            body: {

                size: 0,
                query: {
                    bool: {
                        must: [
                            {
                                term: {
                                    network: req.searchIp
                                }
                            }
                        ]
                    }
                },
                "aggs": {
                    "id_agg": {
                        "terms": { "field": "id" }
                    }
                }
            }
        };


        const result = await this.client.search(request) as any;
        return { items: result?.aggregations?.id_agg?.buckets?.map((x: any) => x.key) as string[] || [] }

    }

    async deleteIpIntelligenceList(req: DeleteIpIntelligenceListRequest) {
        await this.createClient();
        if (req.page == undefined) {
            //delete index
            const del = this.getIndexName(`ip-intelligence-list-${req.id.toLowerCase()}`);
            await this.deleteIndexes([del])
            this.ipIntelligenceListIndexes.delete(del);
            return { deletedCount: 1 }
        } else {
            //delete by query
            let request = {
                ignore_unavailable: true,
                index: `ip-intelligence-list-${req.id.toLowerCase()}`,
                body: {


                    query: {
                        bool: {
                            must: [
                                {
                                    term: {
                                        id: req.id
                                    }
                                },
                                {
                                    term: {
                                        page: req.page
                                    }
                                }
                            ]
                        }
                    }
                }
            };


            const result = await this.client.deleteByQuery(request);
            return { deletedCount: result.deleted }
        }

    }

    async scrollIpIntelligenceList(req: ScrollIpIntelligenceListRequest, cont: () => boolean, callback: (item: IpIntelligenceListItem) => Promise<void>) {
        await this.createClient();
        //proxy does not support scroll
        /*  let request = {
             ignore_unavailable: true,
             index: this.getIndexName(`ip-intelligence-list-${req.id ? req.id.toLowerCase() : '*'}`),
             scroll: '1m',
             body: {
                 query: {
                     "match_all": {}
                 }
 
             }
         };
 
         let { _scroll_id, hits } = await this.client.search(request, {}) as any;
 
         while (cont() && hits && hits.hits.length) {
             for (const item of hits.hits.map((x: any) => x._source)) {
                 await callback(item);
             }
             let result = await this.client.scroll({ scroll_id: _scroll_id, scroll: '1m' })
             _scroll_id = result._scroll_id;
             hits = result.hits;
         } */
        let request = {
            ignore_unavailable: true,
            index: this.getIndexName(`ip-intelligence-list-${req.id ? req.id.toLowerCase() : '*'}`),
            size: 100000,
            body: {
                query: {
                    "match_all": {}
                }

            }
        };

        let result = await this.client.search(request, {}) as any;
        for (const item of result.hits.hits.map((x: any) => x._source)) {
            await callback(item);
        }

    }







    addToQuery(item: string | undefined, field: string, dest: any[]) {

        const items = item?.split(',');
        if (items?.length) {
            let item = {
                bool: {
                    should: items.map(x => {
                        let val =
                        {
                            term: {} as any
                        };
                        val.term[field] = x;
                        return val;
                    })
                }
            };
            dest.push(item as never);
        }

    }
    addToQueryBoolean(val: boolean | undefined, field: string, dest: any[]) {

        if (!Util.isUndefinedOrNull(val)) {
            let query =
            {
                term: {} as any
            };
            query.term[field] = val;
            let item = {
                bool: {
                    should: query
                }
            };
            dest.push(item as never);
        }

    }
    addToQueryNumber(val: number | undefined, field: string, dest: any[]) {

        if (!Util.isUndefinedOrNull(val)) {
            let query =
            {
                term: {} as any
            };
            query.term[field] = val;
            let item = {
                bool: {
                    should: query
                }
            };
            dest.push(item as never);
        }

    }


    async searchAuditLogs(req: SearchAuditLogsRequest) {
        await this.createClient();
        let request = {
            ignore_unavailable: true,
            index: this.getIndexName('ferrumgate-audit'),
            body: {
                from: (req.page || 0) * (req.pageSize || 10),
                size: (req.pageSize || 10),
                sort: { "insertDate": "desc" },
                query: {
                    bool: {
                        must: [

                        ]
                    }
                }
            }
        };
        request.body.query.bool.must.push({
            "range": {
                "insertDate": {
                    "gte": req.startDate ? req.startDate : ('now-1d'),
                    "lt": req.endDate ? req.endDate : ('now')
                }
            }
        } as never);
        this.addToQuery(req.username, 'username', request.body.query.bool.must);
        this.addToQuery(req.message, 'message', request.body.query.bool.must);
        if (req.search) {

            let item = {
                query_string: {
                    query: `${req.search}`,
                    fields: ['username', "userId", "ip", "message", "messageDetail", "messageSummary", "tags"]
                }
            }
            request.body.query.bool.must.push(item as never);

        }

        const result = await this.client.search(request) as any;
        return { total: result?.hits?.total?.value as number || 0, items: result?.hits.hits.map((x: any) => x._source) as ESAuditLog[] }

    }
    dateFormat(val: string | Date | number) {
        let date = new Date(val);
        let year = date.getUTCFullYear();
        let month = (date.getUTCMonth() + 1).toString();
        if ((date.getUTCMonth() + 1) < 10) month = `0${month}`;
        let day = date.getUTCDate().toString();
        if (date.getUTCDate() < 10)
            day = `0${day}`;
        return `${year}${month}${day}`;
    }



    ////activity 
    async activityCreateIndexIfNotExits(item: ActivityLog): Promise<[ESActivityLog, string]> {
        await this.createClient();
        let index = this.getIndexName(`ferrumgate-activity-${this.dateFormat(item.insertDate)}`);
        let esitem: ESActivityLog =
        {
            ...item

        };
        const foundedIndex = this.activityIndexes.get(index);
        if (foundedIndex || 0 > new Date().getTime()) return [esitem, index];

        let exists = (await this.client.indices.exists({ index: index }));
        if (!exists) {


            await this.client.indices.create({
                index: index,
                body: {
                    settings: {
                        index: {
                            number_of_replicas: Number(process.env.ES_REPLICAS) || 2,
                            number_of_shards: Number(process.env.ES_SHARDS) || 1,
                            "refresh_interval": this.refreshInterval,
                            translog: {
                                "durability": "async",
                                "sync_interval": "10s",
                                "flush_threshold_size": "1gb"
                            }
                        }
                    },
                    mappings: {


                        properties: {
                            insertDate: {
                                type: 'date', // type is a required attribute if index is specified

                            },
                            requestId: {
                                type: "keyword"
                            },
                            type: {
                                type: "keyword"

                            },
                            authSource: {
                                type: "keyword"

                            },
                            ip: {
                                type: "keyword",
                                fields: {
                                    addr: {
                                        type: 'ip'
                                    }
                                }

                            },

                            status: {
                                type: "integer"

                            },
                            statusMessage: {
                                type: "keyword"

                            },
                            statusMessageDetail: {
                                type: "keyword"

                            },
                            username: {
                                type: "keyword"

                            },
                            userId: {
                                type: "keyword"

                            },
                            requestPath: {
                                type: "keyword"

                            },
                            user2FA: {
                                type: "boolean"

                            },
                            sessionId: {
                                type: "keyword"

                            },
                            is2FA: {
                                type: "boolean"

                            },
                            trackId: {
                                type: "long"

                            },
                            assignedIp: {
                                type: "keyword",
                                fields: {
                                    addr: {
                                        type: 'ip'
                                    }
                                }

                            },
                            tunnelId: {
                                type: "keyword"

                            },
                            serviceId: {
                                type: "keyword"

                            },
                            serviceName: {
                                type: "keyword"

                            },
                            serviceProtocol: {
                                type: "keyword"

                            },
                            gatewayId: {
                                type: "keyword"

                            },
                            gatewayName: {
                                type: "keyword"
                            },
                            tun: {
                                type: "keyword"
                            },
                            tunType: {
                                type: "keyword"
                            },
                            authnId: {
                                type: "keyword"

                            },
                            authnName: {
                                type: "keyword"

                            },
                            authzId: {
                                type: "keyword"

                            },
                            authzName: {
                                type: "keyword"

                            },
                            deviceId: {
                                type: "keyword"
                            },
                            deviceName: {
                                type: "keyword"
                            },
                            osName: {
                                type: "keyword"
                            },
                            osVersion: {
                                type: "keyword"
                            },
                            browser: {
                                type: "keyword"
                            },
                            browserVersion: {
                                type: "keyword"
                            },
                            countryName: {
                                type: "keyword"
                            },
                            countryCode: {
                                type: "keyword"
                            },
                            sourceIp: {
                                type: "keyword",
                                fields: {
                                    addr: {
                                        type: 'ip'
                                    }
                                }
                            },
                            sourcePort: {
                                type: "integer"
                            },
                            destinationIp: {
                                type: "keyword",
                                fields: {
                                    addr: {
                                        type: 'ip'
                                    }
                                }
                            },

                            destinationPort: {
                                type: "integer"
                            },
                            networkProtocol: {
                                type: "keyword"
                            },
                            isProxyIp: {
                                type: 'boolean'
                            },
                            isHostingIp: {
                                type: 'boolean'
                            },
                            isCrawlerIp: {
                                type: 'boolean'
                            },
                            dnsQueryType: {
                                type: "keyword"
                            },
                            dnsQuery: {
                                type: "keyword"
                            },
                            dnsStatus: {
                                type: "keyword"
                            },
                            dnsFqdnCategoryId: {
                                type: "keyword"
                            },
                            dnsFqdnCategoryName: {
                                type: "keyword"
                            }


                        }

                    }
                }
            })


        }
        this.activityIndexes.set(index, new Date().getTime() + ThreeMinutes);
        return [esitem, index];
    }

    async activitySave(items: [ESActivityLog, string][]): Promise<void> {
        await this.createClient();
        let indexList = new Set<string>();
        items.forEach(x => {
            indexList.add(x[1]);
        });
        indexList.forEach(async x => {
            let result: any[] = [];
            let mapped = items.filter(y => y[1] == x).map(doc => [{ index: { _index: this.getIndexName(doc[1]) } }, doc[0]])
            mapped.forEach(x => {
                result = result.concat(x);
            });
            await this.client.bulk({
                index: this.getIndexName(x),
                body: result
            })
        });
    }

    dayBefore(miliseconds: number, start?: Date) {
        let s = start || new Date();
        return new Date(s.getTime() - miliseconds);
    }

    OneDayMS = 24 * 60 * 60 * 1000;
    indexCalculator(sDate: Date, eDate: Date) {
        let items: Set<string> = new Set();
        let i = 0;
        let sDateNumber = sDate.getTime();
        let eDateNumber = eDate.getTime();

        let start = Math.min(sDateNumber, eDateNumber);
        let end = Math.max(sDateNumber, eDateNumber);
        while (start < end + this.OneDayMS) {
            items.add(this.dateFormat(start));
            start += this.OneDayMS;
        }
        return Array.from(items);

    }
    async searchActivityLogs(req: SearchActivityLogsRequest) {
        await this.createClient();
        let sDate = req.startDate ? new Date(req.startDate) : this.dayBefore(this.OneDayMS);
        let eDate = req.endDate ? new Date(req.endDate) : new Date();
        const dates = this.indexCalculator(sDate, eDate);
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith(this.getIndexName('ferrumgate-activity-')));
        let cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => this.getIndexName(`ferrumgate-activity-${x}`));
        if (!cindexes.length)
            cindexes = dates.map(x => this.getIndexName(`ferrumgate-activity-${x}`));
        let request = {
            ignore_unavailable: true,
            index: cindexes,
            body: {
                from: (req.page || 0) * (req.pageSize || 10),
                size: (req.pageSize || 10),
                sort: { "insertDate": "desc" },
                query: {
                    bool: {
                        must: [

                        ]
                    }
                }
            }
        };
        request.body.query.bool.must.push({
            "range": {
                "insertDate": {
                    "gte": req.startDate ? req.startDate : ('now-1d'),
                    "lt": req.endDate ? req.endDate : ('now')
                }
            }
        } as never);
        this.addToQuery(req.requestId, 'requestId', request.body.query.bool.must);
        this.addToQuery(req.type, 'type', request.body.query.bool.must);
        this.addToQuery(req.authSource, 'authSource', request.body.query.bool.must);
        this.addToQuery(req.ip, 'ip', request.body.query.bool.must);
        this.addToQuery(req.statusMessage, 'statusMessage', request.body.query.bool.must);
        this.addToQuery(req.statusMessageDetail, 'statusMessageDetail', request.body.query.bool.must);
        this.addToQuery(req.username, 'username', request.body.query.bool.must);
        this.addToQuery(req.sessionId, 'sessionId', request.body.query.bool.must);
        this.addToQuery(req.serviceName, 'serviceName', request.body.query.bool.must);
        this.addToQuery(req.networkId, 'networkId', request.body.query.bool.must);
        this.addToQuery(req.networkName, 'networkName', request.body.query.bool.must);
        this.addToQuery(req.gatewayId, 'gatewayId', request.body.query.bool.must);
        this.addToQuery(req.gatewayName, 'gatewayName', request.body.query.bool.must);
        this.addToQueryBoolean(req.is2FA, 'is2FA', request.body.query.bool.must);
        this.addToQueryNumber(req.status, 'status', request.body.query.bool.must);

        if (req.search) {

            let item = {
                query_string: {
                    query: `${req.search}`,
                    fields: ['requestId', "type", "authSource", "ip", "statusMessage", "statusMessage2", "serviceId", "serviceName", "assignedIp", "sourceIp", "destinationIp",
                        "username", "userId", "gatewayId", "gatewayName", "networkId", "networkName", "authnId", "authnName", "authzId", "authzName", "dnsFqdnCategoryId", "dnsQuery", "dnsFqdnCategoryName"]
                }
            }
            request.body.query.bool.must.push(item as never);

        }
        console.log(JSON.stringify(request));
        const result = await this.client.search(request) as any;
        let returnResult = { total: result?.hits?.total?.value as number || 0, items: result?.hits.hits.map((x: any) => x._source) as ESActivityLog[] }
        return returnResult;

    }

    private getSummaryQuery(type: string, start: string, end: string, aggField: string, interval: string, timezone: string) {
        return {
            "size": 0,
            "sort": {
                "insertDate": "asc"
            },
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "insertDate": {
                                    "gte": start,
                                    "lt": end
                                }
                            }
                        },
                        {
                            "term": {
                                "type": type
                            }
                        }
                    ],
                    "must_not": []
                }
            },
            "aggs": {
                "insertDate": {
                    "date_histogram": {
                        "field": "insertDate",
                        "calendar_interval": interval,
                        "min_doc_count": 0,
                        "time_zone": timezone,
                        "extended_bounds": { "min": start, "max": end }
                    },
                    "aggs": {
                        [aggField]: {
                            "terms": {
                                "field": aggField
                            }
                        }
                    }
                }
            }
        }
    }

    private getSummaryLast7Days(_start?: Date, _end?: Date) {
        const now = _end || new Date();
        const tmp = _start || new Date(new Date().getTime() - (6 * this.OneDayMS))
        tmp.setUTCHours(0, 0, 0);
        return { start: tmp.toISOString(), end: now.toISOString() };
    }

    private getSummaryDates(request: SearchSummaryRequest) {
        return this.getSummaryLast7Days(
            request.startDate ? new Date(request.startDate) : undefined,
            request.endDate ? new Date(request.endDate) : undefined);
    }

    async getSummaryLoginTry(sreq: SearchSummaryRequest) {
        await this.createClient();
        const { start, end } = this.getSummaryDates(sreq);


        const dates = this.indexCalculator(new Date(start), new Date(end));
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith(this.getIndexName('ferrumgate-activity-')));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => this.getIndexName(`ferrumgate-activity-${x}`));
        const srequest = this.getSummaryQuery('login try', start, end, 'status', 'day', sreq.timeZone || '+00:00');
        console.log(JSON.stringify(srequest));
        let request = {
            ignore_unavailable: true,
            index: cindexes,
            body: srequest
        };
        request.body.query.bool.must_not.push(
            {
                "term": {
                    "authSource": "tunnelKey"
                }
            } as never
        )
        const result = await this.client.search(request) as any;
        let retVal: ESAgg = {
            total: result.hits.total.value,
            aggs: result.aggregations?.insertDate?.buckets?.map((x: any) => {
                return {
                    key: x.key, value: x.doc_count,
                    sub: x.status?.buckets?.map((y: any) => {
                        return {
                            key: y.key, value: y.doc_count
                        }
                    })
                }
            }) || []
        }
        return retVal;
    }



    async getSummary2faCheck(sreq: SearchSummaryRequest) {
        await this.createClient();
        const { start, end } = this.getSummaryDates(sreq);


        const dates = this.indexCalculator(new Date(start), new Date(end));
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith(this.getIndexName('ferrumgate-activity-')));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => this.getIndexName(`ferrumgate-activity-${x}`))
        const srequest = this.getSummaryQuery('2fa check', start, end, 'status', 'day', sreq.timeZone || '+00:00');
        console.log(JSON.stringify(srequest));
        let request = {
            ignore_unavailable: true,
            index: cindexes,
            body: srequest
        };
        const result = await this.client.search(request) as any;
        let retVal: ESAgg = {
            total: result.hits.total.value,
            aggs: result.aggregations?.insertDate?.buckets?.map((x: any) => {
                return {
                    key: x.key, value: x.doc_count,
                    sub: x.status?.buckets?.map((y: any) => {
                        return {
                            key: y.key, value: y.doc_count
                        }
                    })
                }
            }) || []
        }
        return retVal;
    }



    getSummaryQueryLoginUser(start: string, end: string, size = 10) {
        return {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "insertDate": {
                                    "gte": start,
                                    "lt": end
                                }
                            }
                        },
                        {
                            "term": {
                                "type": "login try"
                            }
                        },
                    ],
                    "must_not": [
                        {
                            "term": {
                                "authSource": "tunnelKey"
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "username": {
                    "terms": {
                        "field": "username",
                        "size": size,
                        "order": {
                            "_count": "desc"
                        }

                    }
                }
            }
        }
    }

    /**
     * @summary top 10 user logined success
     * @param sreq
     * @returns 
     */
    async getSummaryUserLoginSuccess(sreq: SearchSummaryRequest) {
        await this.createClient();
        const { start, end } = this.getSummaryDates(sreq);


        const dates = this.indexCalculator(new Date(start), new Date(end));
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith(this.getIndexName('ferrumgate-activity-')));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => this.getIndexName(`ferrumgate-activity-${x}`));
        const srequest = this.getSummaryQueryLoginUser(start, end);
        srequest.query.bool.must.push({
            "term": {
                "status": 200
            }
        } as any)

        console.log(JSON.stringify(srequest));
        let request = {
            ignore_unavailable: true,
            index: cindexes,
            body: srequest
        };
        const result = await this.client.search(request) as any;
        let retVal: ESAgg = {
            total: result.hits.total.value,
            aggs: result.aggregations?.username?.buckets?.map((x: any) => {
                return {
                    key: x.key, value: x.doc_count,
                }
            }) || []
        }
        return retVal;
    }

    /**
     * @summary top10 user login failed
     * @param sreq 
     * @returns 
     */
    async getSummaryUserLoginFailed(sreq: SearchSummaryRequest) {
        await this.createClient();
        const { start, end } = this.getSummaryDates(sreq);


        const dates = this.indexCalculator(new Date(start), new Date(end));
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith(this.getIndexName('ferrumgate-activity-')));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => this.getIndexName(`ferrumgate-activity-${x}`))
        const srequest = this.getSummaryQueryLoginUser(start, end);
        srequest.query.bool.must_not.push(
            {
                "term": {
                    "status": 200
                }
            } as never);

        console.log(JSON.stringify(srequest));
        let request = {
            ignore_unavailable: true,
            index: cindexes,
            body: srequest
        };
        const result = await this.client.search(request) as any;
        let retVal: ESAgg = {
            total: result.hits.total.value,
            aggs: result.aggregations?.username?.buckets?.map((x: any) => {
                return {
                    key: x.key, value: x.doc_count,
                }
            }) || []
        }
        return retVal;
    }

    async getSummaryCreateTunnel(sreq: SearchSummaryRequest) {
        await this.createClient();
        const { start, end } = this.getSummaryDates(sreq);

        const dates = this.indexCalculator(new Date(start), new Date(end));
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith(this.getIndexName('ferrumgate-activity-')));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => this.getIndexName(`ferrumgate-activity-${x}`));
        const srequest = this.getSummaryQuery('create tunnel', start, end, 'tunType', 'day', sreq.timeZone || '+00:00');
        console.log(JSON.stringify(srequest));
        let request = {
            ignore_unavailable: true,
            index: cindexes,
            body: srequest
        };
        const result = await this.client.search(request) as any;
        let retVal: ESAgg = {
            total: result.hits.total.value,
            aggs: result.aggregations?.insertDate?.buckets?.map((x: any) => {
                return {
                    key: x.key, value: x.doc_count,
                    sub: x.tunType?.buckets?.map((y: any) => {
                        return {
                            key: y.key, value: y.doc_count
                        }
                    })
                }
            }) || []
        }
        return retVal;
    }

    async getSummaryUserLoginTry(sreq: SearchSummaryUserRequest) {
        await this.createClient();
        const { start, end } = this.getSummaryDates(sreq);


        const dates = this.indexCalculator(new Date(start), new Date(end));
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith(this.getIndexName('ferrumgate-activity-')));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => this.getIndexName(`ferrumgate-activity-${x}`));
        const srequest = this.getSummaryQuery('login try', start, end, 'status', 'day', sreq.timeZone || '+00:00');
        console.log(JSON.stringify(srequest));
        let request = {
            ignore_unavailable: true,
            index: cindexes,
            body: srequest
        };
        request.body.query.bool.must.push({
            "term": {
                "username": sreq.username
            } as any
        })
        request.body.query.bool.must_not.push(
            {
                "term": {
                    "authSource": "tunnelKey"
                }
            } as never
        )
        const result = await this.client.search(request) as any;
        let retVal: ESAgg = {
            total: result.hits.total.value,
            aggs: result.aggregations?.insertDate?.buckets?.map((x: any) => {
                return {
                    key: x.key, value: x.doc_count,
                    sub: x.status?.buckets?.map((y: any) => {
                        return {
                            key: y.key, value: y.doc_count
                        }
                    })
                }
            }) || []
        }
        return retVal;
    }


    async getSummaryUserLoginTryHours(sreq: SearchSummaryUserRequest) {
        await this.createClient();
        const { start, end } = this.getSummaryDates(sreq);


        const dates = this.indexCalculator(new Date(start), new Date(end));
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith(this.getIndexName('ferrumgate-activity-')));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => this.getIndexName(`ferrumgate-activity-${x}`));
        const srequest = this.getSummaryQuery('login try', start, end, 'status', 'hour', sreq.timeZone || '+00:00');
        console.log(JSON.stringify(srequest));
        let request = {
            ignore_unavailable: true,
            index: cindexes,
            body: srequest
        };
        request.body.query.bool.must.push({
            "term": {
                "username": sreq.username
            } as any
        })
        request.body.query.bool.must_not.push(
            {
                "term": {
                    "authSource": "tunnelKey"
                }
            } as never
        )
        const result = await this.client.search(request) as any;
        let retVal: ESAgg = {
            total: result.hits.total.value,
            aggs: result.aggregations?.insertDate?.buckets?.map((x: any) => {
                return {
                    key: x.key, value: x.doc_count,
                    sub: x.status?.buckets?.map((y: any) => {
                        return {
                            key: y.key, value: y.doc_count
                        }
                    })
                }
            }) || []
        }
        return retVal;
    }





    ////device 
    async deviceCreateIndexIfNotExits(item: DeviceLog): Promise<[ESDeviceLog, string]> {
        await this.createClient();
        let index = this.getIndexName(`ferrumgate-device-${this.dateFormat(item.insertDate)}`);
        let esitem: ESDeviceLog =
        {
            ...item

        };
        const foundedIndex = this.deviceIndexes.get(index);
        if ((foundedIndex || 0) > new Date().getTime()) return [esitem, index];

        let exists = (await this.client.indices.exists({ index: index }));
        if (!exists) {


            await this.client.indices.create({
                index: index,
                body: {
                    settings: {
                        index: {
                            number_of_replicas: Number(process.env.ES_REPLICAS) || 2,
                            number_of_shards: Number(process.env.ES_SHARDS) || 1,
                            "refresh_interval": this.refreshInterval,
                            translog: {
                                "durability": "async",
                                "sync_interval": "10s",
                                "flush_threshold_size": "1gb"
                            }


                        }
                    },
                    mappings: {


                        properties: {
                            insertDate: {
                                type: 'date', // type is a required attribute if index is specified

                            },
                            id: {
                                type: "keyword"
                            },
                            userId: {
                                type: "keyword"

                            },
                            username: {
                                type: "keyword"

                            },
                            hostname: {
                                type: "keyword"

                            },
                            osName: {
                                type: "keyword"

                            },
                            osVersion: {
                                type: "keyword"

                            },
                            macs: {
                                type: "keyword"

                            },
                            serial: {
                                type: "keyword"

                            },
                            clientVersion: {
                                type: "keyword"

                            },
                            clientSha256: {
                                type: "keyword"

                            },
                            platform: {
                                type: "keyword"

                            },

                            hasEncryptedDisc: {
                                type: "boolean"

                            },
                            hasFirewall: {
                                type: "boolean"

                            },
                            hasAntivirus: {
                                type: "boolean"

                            },
                            isHealthy: {
                                type: "boolean"

                            },
                            whyNotHealthy: {
                                type: "keyword",

                            },
                            networkId: {
                                type: "keyword"

                            },
                            networkName: {
                                type: "keyword"

                            },

                        }

                    }
                }
            })


        }
        this.deviceIndexes.set(index, new Date().getTime() + ThreeMinutes);
        return [esitem, index];
    }

    async deviceSave(items: [ESDeviceLog, string][]): Promise<void> {
        await this.createClient();
        let indexList = new Set<string>();
        items.forEach(x => {
            indexList.add(x[1]);
        });
        indexList.forEach(async x => {
            let result: any[] = [];
            let mapped = items.filter(y => y[1] == x).map(doc => [{ index: { _index: this.getIndexName(doc[1]) } }, doc[0]])
            mapped.forEach(x => {
                result = result.concat(x);
            });
            await this.client.bulk({
                index: this.getIndexName(x),
                body: result
            })
        });
    }


    async searchDeviceLogs(req: SearchDeviceLogsRequest) {
        await this.createClient();
        let sDate = req.startDate ? new Date(req.startDate) : this.dayBefore(this.OneDayMS);
        let eDate = req.endDate ? new Date(req.endDate) : new Date();
        const dates = this.indexCalculator(sDate, eDate);
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith(this.getIndexName('ferrumgate-device-')));
        let cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => this.getIndexName(`ferrumgate-device-${x}`));
        if (!cindexes.length)
            cindexes = dates.map(x => this.getIndexName(`ferrumgate-device-${x}`));
        let request = {
            ignore_unavailable: true,
            index: cindexes,
            body: {
                from: (req.page || 0) * (req.pageSize || 10),
                size: (req.pageSize || 10),
                sort: { "insertDate": "desc" },
                query: {
                    bool: {
                        must: [

                        ]
                    }
                }
            }
        };
        request.body.query.bool.must.push({
            "range": {
                "insertDate": {
                    "gte": req.startDate ? req.startDate : ('now-1d'),
                    "lt": req.endDate ? req.endDate : ('now')
                }
            }
        } as never);
        this.addToQuery(req.id, 'id', request.body.query.bool.must);
        this.addToQueryBoolean(req.isHealthy, 'isHealthy', request.body.query.bool.must);

        if (req.search) {

            let item = {
                query_string: {
                    query: `${req.search}`,
                    fields: ['id', "hostname", "osName", "osVersion", "macs", "serial", "platform", "clientVersion", "userId", "username", "networkId", "networkName"]
                }
            }
            request.body.query.bool.must.push(item as never);

        }

        console.log(JSON.stringify(request));
        const result = await this.client.search(request) as any;
        let returnResult = { total: result?.hits?.total?.value as number || 0, items: result?.hits.hits.map((x: any) => x._source) as ESActivityLog[] }
        return returnResult;

    }

    // fqdn intelligence 
    // we are not using 

    async fqdnIntelligenceListCreateIndexIfNotExits(item: FqdnIntelligenceListItem): Promise<[ESFqdnIntelligenceListItem, string]> {
        await this.createClient();
        let date = Date.now();
        let index = this.getIndexName(`fqdn-intelligence-list-${item.id.toLowerCase()}`);
        let esitem: ESFqdnIntelligenceListItem =
        {
            ...item

        };
        const foundedIndex = this.fqdnIntelligenceListIndexes.get(index);
        if ((foundedIndex || 0) > new Date().getTime()) return [esitem, index];

        let exists = (await this.client.indices.exists({ index: index }));
        if (!exists) {


            await this.client.indices.create({
                index: index,
                body: {
                    settings: {
                        index: {
                            number_of_replicas: 1,
                            number_of_shards: 1,
                            "refresh_interval": this.refreshInterval,
                            translog: {
                                "durability": "async",
                                "sync_interval": "10s",
                                "flush_threshold_size": "1gb"
                            }


                        }
                    },
                    mappings: {


                        properties: {
                            insertDate: {
                                type: 'date', // type is a required attribute if index is specified

                            },

                            id: {
                                type: "keyword"

                            },

                            page: {
                                type: "integer"

                            },
                            fqdn: {
                                type: "keyword",


                            }
                        }

                    }
                }
            })


        }
        this.fqdnIntelligenceListIndexes.set(index, new Date().getTime() + ThreeMinutes);
        return [esitem, index];
    }

    async fqdnIntelligenceListItemSave(items: [ESFqdnIntelligenceListItem, string][]): Promise<void> {
        await this.createClient();

        let indexList = new Set<string>();
        items.forEach(x => {
            indexList.add(x[1]);
        });
        indexList.forEach(async x => {
            let result: any[] = [];
            let mapped = items.filter(y => y[1] == x).map(doc => [{ index: { _index: this.getIndexName(doc[1]) } }, doc[0]])
            mapped.forEach(x => {
                result = result.concat(x);
            });
            await this.client.bulk({
                index: this.getIndexName(x),
                body: result
            })
        });
    }

    async searchFqdnIntelligenceList(req: SearchFqdnIntelligenceListRequest) {
        await this.createClient();
        let request = {
            ignore_unavailable: true,
            index: this.getIndexName(`fqdn-intelligence-list-${req.id ? req.id.toLowerCase() : '*'}`),
            body: {

                size: 0,
                query: {
                    bool: {
                        must: [
                            {
                                term: {
                                    fqdn: req.searchFqdn
                                }
                            }
                        ]
                    }
                },
                "aggs": {
                    "id_agg": {
                        "terms": { "field": "id" }
                    }
                }
            }
        };


        const result = await this.client.search(request) as any;
        return { items: result?.aggregations?.id_agg?.buckets?.map((x: any) => x.key) as string[] || [] }

    }
    async deleteFqdnIntelligenceList(req: DeleteFqdnIntelligenceListRequest) {
        await this.createClient();
        if (req.page == undefined) {
            //delete index
            const del = this.getIndexName(`fqdn-intelligence-list-${req.id.toLowerCase()}`);
            await this.deleteIndexes([del])
            this.ipIntelligenceListIndexes.delete(del);
            return { deletedCount: 1 }
        } else {
            //delete by query
            let request = {
                ignore_unavailable: true,
                index: this.getIndexName(`fqdn-intelligence-list-${req.id.toLowerCase()}`),
                body: {


                    query: {
                        bool: {
                            must: [
                                {
                                    term: {
                                        id: req.id
                                    }
                                },
                                {
                                    term: {
                                        page: req.page
                                    }
                                }
                            ]
                        }
                    }
                }
            };


            const result = await this.client.deleteByQuery(request);
            return { deletedCount: result.deleted }
        }

    }

    async scrollFqdnIntelligenceList(req: ScrollIpIntelligenceListRequest, cont: () => boolean, callback: (item: FqdnIntelligenceListItem) => Promise<void>) {
        await this.createClient();
        //proxy does not support scroll
        /* let request = {
            ignore_unavailable: true,
            index: this.getIndexName(`fqdn-intelligence-list-${req.id ? req.id.toLowerCase() : '*'}`),
            scroll: '1m',
            body: {
                query: {
                    "match_all": {}
                }

            }
        };


        let { _scroll_id, hits } = await this.client.search(request, {}) as any;

        while (cont() && hits && hits.hits.length) {
            for (const item of hits.hits.map((x: any) => x._source)) {
                await callback(item);
            }
            let result = await this.client.scroll({ scroll_id: _scroll_id, scroll: '1m' })
            _scroll_id = result._scroll_id;
            hits = result.hits;
        } */

        let request = {
            ignore_unavailable: true,
            index: this.getIndexName(`fqdn-intelligence-list-${req.id ? req.id.toLowerCase() : '*'}`),
            size: 100000,
            body: {
                query: {
                    "match_all": {}
                }

            }
        };


        let result = await this.client.search(request, {}) as any;
        for (const item of result.hits.hits.map((x: any) => x._source)) {
            await callback(item);
        }
    }
}


export class ESServiceLimited extends ESService {
    override async reConfigure(host: string, username?: string | undefined, password?: string | undefined, refresh_interval?: string | undefined): Promise<void> {

    }
    override async auditCreateIndexIfNotExits(item: AuditLog): Promise<[ESAuditLog, string]> {

        return [{ ...item }, this.getIndexName('ferrumgate-audit')];

    }
    override async auditSave(items: [ESAuditLog, string][]): Promise<void> {

        await fsp.appendFile(`/var/log/ferrumgate/audit-${this.dateFormat(new Date())}`, JSON.stringify(items.map(x => x[0])) + '\n');

    }

    override async activityCreateIndexIfNotExits(item: ActivityLog): Promise<[ESActivityLog, string]> {
        let index = this.getIndexName(`ferrumgate-activity-${this.dateFormat(item.insertDate)}`);
        let esitem: ESActivityLog =
        {
            ...item

        };
        return [esitem, index];
    }
    override async activitySave(items: [ESActivityLog, string][]): Promise<void> {
        await fsp.appendFile(`/var/log/ferrumgate/activity-${this.dateFormat(new Date())}`, JSON.stringify(items.map(x => x[0])) + '\n');
    }

    override async deviceCreateIndexIfNotExits(item: DeviceLog): Promise<[ESDeviceLog, string]> {
        let index = this.getIndexName(`ferrumgate-device-${this.dateFormat(item.insertDate)}`);
        let esitem: ESDeviceLog =
        {
            ...item

        };
        return [esitem, index];
    }
    override async deviceSave(items: [ESDeviceLog, string][]): Promise<void> {
        await fsp.appendFile(`/var/log/ferrumgate/device-${this.dateFormat(new Date())}`, JSON.stringify(items.map(x => x[0])) + '\n');
    }
}


/**
 * The same code below, that inherits from ESServiceLimited
 */
export class ESServiceExtended extends ESService {
    /**
     *
     */
    interval: any;
    configService: ConfigService;
    constructor(configService: ConfigService, host?: string, username?: string, password?: string) {
        super(configService, host, username, password);
        this.configService = configService;
        this.configService.events.on('ready', async () => {
            logger.info(`config service is ready`);
            await this.startReconfigureES();
        })
        this.configService.events.on('configChanged', async (evt: ConfigWatch<any>) => {
            if (evt.path.startsWith('/config/es')) {
                logger.info(`es config changed`)
                await this.startReconfigureES();
            }
        })
        this.startReconfigureES();

    }

    public async startReconfigureES() {
        try {

            const es = await this.configService.getES();
            logger.info(`configuring es again ${es.host || ''}`)
            if (es.host)
                await this.reConfigure(es.host, es.user, es.pass);
            else
                await this.reConfigure(process.env.ES_HOST || 'https://localhost:9200', process.env.ES_USER, process.env.ES_PASS);
            if (this.interval)
                clearIntervalAsync(this.interval);
            this.interval = null;

        } catch (err) {
            logger.error(err);
            if (!this.interval) {
                this.interval = setIntervalAsync(async () => {
                    await this.startReconfigureES();
                }, 5000);

            }
        }
    }
    public async stop() {
        if (this.interval)
            clearIntervalAsync(this.interval);
        this.interval = null;
    }
}

export class ESServiceFerrumCloud extends ESService {

    constructor(configService: ConfigService, host?: string, username?: string, password?: string) {
        super(configService, host, username, password);
        this.host = process.env.ES_MULTI_HOST;
        this.username = process.env.ES_MULTI_USER;
        this.password = process.env.ES_MULTI_PASS;
    }
}







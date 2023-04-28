import * as ES from '@elastic/elasticsearch'
import { json } from 'body-parser';
import { query, response } from 'express';
import { Util } from '../util';
import { ActivityLog } from '../model/activityLog';
//import dateformat from 'dateformat'
import { AuditLog } from '../model/auditLog';
import { ConfigService } from './configService';
import fsp from 'fs/promises';
import { ESSetting } from '../model/esSetting';
import { logger } from '../common';
import { RedisConfigWatchCachedService } from './redisConfigWatchCachedService';
import { RedisConfigService } from './redisConfigService';
import { ConfigWatch } from '../model/config';
import { IpIntelligenceList, IpIntelligenceListItem } from '../model/IpIntelligence';
import { BroadcastService } from './broadcastService';
import { DeviceLog } from '../model/device';

const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');



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


/**
 * @summary elastic service
 */
export class ESService {

    private auditIndexes: Map<string, string> = new Map<string, string>();
    private activityIndexes: Map<string, string> = new Map<string, string>();
    private deviceIndexes: Map<string, string> = new Map<string, string>();
    private ipIntelligenceListIndexes: Map<string, string> = new Map<string, string>();
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
        this.auditIndexes = new Map<string, string>();
        this.activityIndexes = new Map<string, string>();
        this.ipIntelligenceListIndexes = new Map<string, string>();
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


    async search(request: any): Promise<any> {
        await this.createClient();
        request.ignore_unavailable = true;
        return await this.client.search(request);

    }
    async getAllIndexes() {
        await this.createClient();
        const indexes = await this.client.cat.indices({ format: 'json' });
        return indexes.filter(x => x.index).map(x => x.index) as string[];
    }
    async reset() {
        await this.createClient();
        const allIndexes = await this.getAllIndexes();
        if (allIndexes.length)
            await this.client.indices.delete({ index: allIndexes })

    }
    async deleteIndexes(indexes: string[]) {
        await this.client.indices.delete({ index: indexes, ignore_unavailable: true })
    }

    async flush(index?: string) {
        await this.createClient();
        await this.client.indices.flush({
            index: index,
            force: true
        });
    }


    ////audit 
    async auditCreateIndexIfNotExits(item: AuditLog): Promise<[ESAuditLog, string]> {
        await this.createClient();
        let date = Date.now();
        // let index = 'ferrum-audit-' + dateformat(item.insertDate, 'yyyymmdd');
        let index = 'ferrumgate-audit';
        let esitem: ESAuditLog =
        {
            ...item

        };
        if (this.auditIndexes.has(index)) return [esitem, index];

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
        this.auditIndexes.set(index, index);
        return [esitem, index];
    }




    async auditSave(items: [ESAuditLog, string][]): Promise<void> {
        await this.createClient();
        let result: any[] = [];
        let mapped = items.map(doc => [{ index: { _index: doc[1] } }, doc[0]])
        mapped.forEach(x => {
            result = result.concat(x);
        });
        await this.client.bulk({
            body: result
        })
    }


    ////ip intelligence list 
    async ipIntelligenceListCreateIndexIfNotExits(item: IpIntelligenceListItem): Promise<[ESIpIntelligenceListItem, string]> {
        await this.createClient();
        let date = Date.now();
        let index = `ip-intelligence-list-${item.id.toLowerCase()}`;
        let esitem: ESIpIntelligenceListItem =
        {
            ...item

        };
        if (this.ipIntelligenceListIndexes.has(index)) return [esitem, index];

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
        this.ipIntelligenceListIndexes.set(index, index);
        return [esitem, index];
    }

    async ipIntelligenceListItemSave(items: [ESIpIntelligenceListItem, string][]): Promise<void> {
        await this.createClient();
        let result: any[] = [];
        let mapped = items.map(doc => [{ index: { _index: doc[1] } }, doc[0]])
        mapped.forEach(x => {
            result = result.concat(x);
        });
        await this.client.bulk({
            body: result
        })
    }

    async searchIpIntelligenceList(req: SearchIpIntelligenceListRequest) {
        await this.createClient();
        let request = {
            ignore_unavailable: true,
            index: `ip-intelligence-list-${req.id ? req.id.toLowerCase() : '*'}`,
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
            const del = `ip-intelligence-list-${req.id.toLowerCase()}`;
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
        let request = {
            ignore_unavailable: true,
            index: `ip-intelligence-list-${req.id ? req.id.toLowerCase() : '*'}`,
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
            index: 'ferrumgate-audit',
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
        let index = `ferrumgate-activity-${this.dateFormat(item.insertDate)}`;
        let esitem: ESActivityLog =
        {
            ...item

        };
        if (this.activityIndexes.has(index)) return [esitem, index];

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
                            }


                        }

                    }
                }
            })


        }
        this.auditIndexes.set(index, index);
        return [esitem, index];
    }

    async activitySave(items: [ESActivityLog, string][]): Promise<void> {
        await this.createClient();
        let result: any[] = [];
        let mapped = items.map(doc => [{ index: { _index: doc[1] } }, doc[0]])
        mapped.forEach(x => {
            result = result.concat(x);
        });
        await this.client.bulk({
            body: result
        })
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
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith('ferrumgate-activity-'));
        let cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => `ferrumgate-activity-${x}`);
        if (!cindexes.length)
            cindexes = dates.map(x => `ferrumgate-activity-${x}`);
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
                        "username", "userId", "gatewayId", "gatewayName", "networkId", "networkName", "authnId", "authnName", "authzId", "authzName"]
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
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith('ferrumgate-activity-'));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => `ferrumgate-activity-${x}`)
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
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith('ferrumgate-activity-'));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => `ferrumgate-activity-${x}`)
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
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith('ferrumgate-activity-'));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => `ferrumgate-activity-${x}`)
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
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith('ferrumgate-activity-'));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => `ferrumgate-activity-${x}`)
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
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith('ferrumgate-activity-'));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => `ferrumgate-activity-${x}`)
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
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith('ferrumgate-activity-'));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => `ferrumgate-activity-${x}`)
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
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith('ferrumgate-activity-'));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => `ferrumgate-activity-${x}`)
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
        let index = `ferrumgate-device-${this.dateFormat(item.insertDate)}`;
        let esitem: ESDeviceLog =
        {
            ...item

        };
        if (this.deviceIndexes.has(index)) return [esitem, index];

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

                            }

                        }

                    }
                }
            })


        }
        this.deviceIndexes.set(index, index);
        return [esitem, index];
    }

    async deviceSave(items: [ESDeviceLog, string][]): Promise<void> {
        await this.createClient();
        let result: any[] = [];
        let mapped = items.map(doc => [{ index: { _index: doc[1] } }, doc[0]])
        mapped.forEach(x => {
            result = result.concat(x);
        });
        await this.client.bulk({
            body: result
        })
    }


    async searchDeviceLogs(req: SearchDeviceLogsRequest) {
        await this.createClient();
        let sDate = req.startDate ? new Date(req.startDate) : this.dayBefore(this.OneDayMS);
        let eDate = req.endDate ? new Date(req.endDate) : new Date();
        const dates = this.indexCalculator(sDate, eDate);
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith('ferrumgate-device-'));
        let cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => `ferrumgate-device-${x}`);
        if (!cindexes.length)
            cindexes = dates.map(x => `ferrumgate-device-${x}`);
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
                    fields: ['id', "hostname", "osName", "osVersion", "macs", "serial", "platform", "clientVersion", "userId", "username"]
                }
            }
            request.body.query.bool.must.push(item as never);

        }

        console.log(JSON.stringify(request));
        const result = await this.client.search(request) as any;
        let returnResult = { total: result?.hits?.total?.value as number || 0, items: result?.hits.hits.map((x: any) => x._source) as ESActivityLog[] }
        return returnResult;

    }

}


export class ESServiceLimited extends ESService {

    override async auditCreateIndexIfNotExits(item: AuditLog): Promise<[ESAuditLog, string]> {

        return [{ ...item }, 'ferrumgate-audit'];

    }
    override async auditSave(items: [ESAuditLog, string][]): Promise<void> {

        await fsp.appendFile(`/var/log/ferrumgate/audit-${this.dateFormat(new Date())}`, JSON.stringify(items.map(x => x[0])) + '\n');

    }

    override async activityCreateIndexIfNotExits(item: ActivityLog): Promise<[ESActivityLog, string]> {
        let index = `ferrumgate-activity-${this.dateFormat(item.insertDate)}`;
        let esitem: ESActivityLog =
        {
            ...item

        };
        return [esitem, index];
    }
    override async activitySave(items: [ESActivityLog, string][]): Promise<void> {
        await fsp.appendFile(`/var/log/ferrumgate/activity-${this.dateFormat(new Date())}`, JSON.stringify(items.map(x => x[0])) + '\n');
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







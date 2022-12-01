import * as ES from '@elastic/elasticsearch'
import { json } from 'body-parser';
import { query } from 'express';
import { Util } from '../util';
import { ActivityLog } from '../model/activityLog';
//import dateformat from 'dateformat'
import { AuditLog } from '../model/auditLog';
import { ConfigService } from './configService';

export interface ESAuditLog extends AuditLog {

}

export interface ESActivityLog extends ActivityLog {

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
    type?: string;//'login try','login success','login deny','service success','service deny','pam activated'
    authSource?: string;//google, apikey
    ip?: string;
    status?: number;//0 success;
    statusMessage?: string;
    statusMessage2?: string;


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
    browser?: string;
    browserVersion?: string;
    requestPath?: string;
}
/**
 * @summary elastic service
 */
export class ESService {



    private auditIndexes: Map<string, string> = new Map<string, string>();
    private activityIndexes: Map<string, string> = new Map<string, string>();
    private client: ES.Client;
    /**
     *  
     */
    constructor(host?: string, username?: string, password?: string) {
        let option: ES.ClientOptions = {
            node: host || 'http://localhost:9200', auth: {
                username: username || '',
                password: password || ''
            },
            tls: { rejectUnauthorized: false },

        }
        this.client = new ES.Client(option);
    }


    async search(request: any): Promise<any> {
        request.ignore_unavailable = true;
        return await this.client.search(request);

    }
    async getAllIndexes() {
        const indexes = await this.client.cat.indices({ format: 'json' });
        return indexes.filter(x => x.index).map(x => x.index) as string[];
    }
    async reset() {
        const allIndexes = await this.getAllIndexes();
        if (allIndexes.length)
            await this.client.indices.delete({ index: allIndexes })

    }

    async flush(index?: string) {
        await this.client.indices.flush({
            index: index,
            force: true
        });
    }


    ////audit 
    async auditCreateIndexIfNotExits(item: AuditLog): Promise<[ESAuditLog, string]> {
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
                            "refresh_interval": "60s",
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
                                type: "keyword"

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

        let result: any[] = [];
        let mapped = items.map(doc => [{ index: { _index: doc[1] } }, doc[0]])
        mapped.forEach(x => {
            result = result.concat(x);
        });
        await this.client.bulk({
            body: result
        })


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



    ////audit 
    async activityCreateIndexIfNotExits(item: ActivityLog): Promise<[ESActivityLog, string]> {

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
                            number_of_replicas: 16,
                            number_of_shards: 16,
                            "refresh_interval": "60s",
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
                                type: "keyword"

                            },
                            status: {
                                type: "integer"

                            },
                            statusMessage: {
                                type: "keyword"

                            },
                            statusMessage2: {
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
                                type: "keyword"

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
        let sDate = req.startDate ? new Date(req.startDate) : this.dayBefore(this.OneDayMS);
        let eDate = req.endDate ? new Date(req.endDate) : new Date();
        const dates = this.indexCalculator(sDate, eDate);
        const indexes = (await this.getAllIndexes()).filter(x => x.startsWith('ferrumgate-activity-'));
        const cindexes = dates.filter(x => indexes.find(y => y.includes(x))).map(x => `ferrumgate-activity-${x}`)
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
        this.addToQuery(req.statusMessage2, 'statusMessage2', request.body.query.bool.must);
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
                    fields: ['requestId', "type", "authSource", "ip", "statusMessage", "statusMessage2", "serviceId", "serviceName",
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


}


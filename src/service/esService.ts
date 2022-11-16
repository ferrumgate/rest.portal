import * as ES from '@elastic/elasticsearch'
import { json } from 'body-parser';
import { query } from 'express';
//import dateformat from 'dateformat'
import { AuditLog } from '../model/auditLog';
import { ConfigService } from './configService';

export interface ESAuditLog extends AuditLog {

}
/**
 * @summary elastic service
 */
export class ESService {



    private auditIndexes: Map<string, string> = new Map<string, string>();
    private client: ES.Client;
    /**
     *  
     */
    constructor(host?: string, username?: string, password?: string) {
        let option: ES.ClientOptions = {
            node: host || process.env.ES_HOST || 'http://localhost:9200', auth: {
                username: username || process.env.ES_USER || '',
                password: password || process.env.ES_PASS || ''
            },
            tls: { rejectUnauthorized: false },

        }
        this.client = new ES.Client(option);
    }
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
            index: 'ferrumgate-audit',
            body: result
        })
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






    async searchAuditLogs(startDate?: string, endDate?: string, search?: string, users?: string, types?: string, page?: number, pageSize?: number) {
        let request = {
            index: 'ferrumgate-audit',
            body: {
                from: (page || 0) * (pageSize || 10),
                size: (pageSize || 10),
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
                    "gte": startDate ? startDate : ('now-1d'),
                    "lt": endDate ? endDate : ('now')
                }
            }
        } as never);

        if (users) {
            const items = users.split(',');
            if (items.length) {
                let item = {
                    bool: {
                        should: items.map(x => {
                            return { term: { username: x } }
                        })
                    }
                };
                request.body.query.bool.must.push(item as never);

            }

        }
        if (types) {
            const items = types.split(',');
            if (items.length) {
                let item = {
                    bool: {
                        should: items.map(x => {
                            return { term: { message: x } }
                        })
                    }
                };
                request.body.query.bool.must.push(item as never);

            }

        }
        if (search) {


            let item = {
                query_string: {
                    query: `*${search}*`,
                    fields: ['username', "userId", "ip", "message", "messageDetail", "messageSummary", "tags"]
                }
            }
            request.body.query.bool.must.push(item as never);

        }
        console.log(JSON.stringify(request));
        const result = await this.client.search(request) as any;
        return { total: result?.hits?.total?.value || 0, items: result?.hits.hits.map((x: any) => x._source) }

    }

    async flush(index?: string) {
        await this.client.indices.flush({
            index: index,
            force: true
        });
    }

}


import { Node, NodeDetail } from "../model/network";
import { Util } from "../util";
import { ConfigService } from "./configService";
import { RedisService } from "./redisService";

/**
 * @summary @see Node related business
 */
export class NodeService {


    constructor(private config: ConfigService, private redisService: RedisService) {
    }

    /**
     * @summary get alive gateways
     * @returns 
     */
    private normalize(x: NodeDetail) {
        x.cpusCount = Util.convertToNumber(x.cpusCount);
        x.totalMem = Util.convertToNumber(x.totalMem);
        x.uptime = Util.convertToNumber(x.uptime);
        x.freeMem = Util.convertToNumber(x.freeMem);
        x.lastSeen = Util.convertToNumber(x.lastSeen);
        return x;
    }
    async getAllAlive(): Promise<NodeDetail[]> {

        const keys = await this.redisService.getAllKeys('/alive/node/id/*', 'hash');
        const pipeline = await this.redisService.pipeline();
        for (const key of keys) {
            await pipeline.hgetAll(key);
        }
        const details = await pipeline.exec() as NodeDetail[];
        //parse string values to numbers
        details.filter(x => x).forEach(x => {
            this.normalize(x);

        })
        return details;
    }
    async saveAlive(detail: NodeDetail) {
        await this.redisService.hset(`/alive/node/id/${detail.id}`, detail);
    }

    async getAliveById(id: string) {
        let key = `/alive/node/id/${id}`;
        const isExists = await this.redisService.containsKey(key);
        if (!isExists) return null;
        const nodeDetail = await this.redisService.hgetAll(key) as unknown as NodeDetail;
        return this.normalize(nodeDetail);
    }
    async deleteAliveById(id: string) {
        let key = `/alive/node/id/${id}`;
        await this.redisService.delete(key);

    }

}
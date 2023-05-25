
import { Util } from "../util";
import { Gateway, GatewayDetail } from "../model/network";
import { ConfigService } from "./configService";
import { RedisService } from "./redisService";

/**
 * @summary @see Gateway related business
 */
export class GatewayService {


    constructor(private config: ConfigService, private redisService: RedisService) {
    }

    /**
     * @summary get alive gateways
     * @returns 
     */
    private normalize(x: GatewayDetail) {
        x.cpusCount = Util.convertToNumber(x.cpusCount);
        x.totalMem = Util.convertToNumber(x.totalMem);
        x.uptime = Util.convertToNumber(x.uptime);
        x.freeMem = Util.convertToNumber(x.freeMem);
        x.lastSeen = Util.convertToNumber(x.lastSeen);
        return x;
    }
    async getAllAlive(): Promise<GatewayDetail[]> {

        const keys = await this.redisService.getAllKeys('/alive/gateway/id/*', 'hash');
        const pipeline = await this.redisService.pipeline();
        for (const key of keys) {
            await pipeline.hgetAll(key);
        }
        const gdetails = await pipeline.exec() as GatewayDetail[];
        //parse string values to numbers
        gdetails.filter(x => x).forEach(x => {
            this.normalize(x);

        })
        return gdetails;
    }

    async getAliveById(id: string) {
        let key = `/alive/gateway/id/${id}`;
        const isExists = await this.redisService.containsKey(key);
        if (!isExists) return null;
        const gatewayDetail = await this.redisService.hgetAll(key) as unknown as GatewayDetail;
        return this.normalize(gatewayDetail);
    }
    async deleteAliveById(id: string) {
        let key = `/alive/gateway/id/${id}`;
        await this.redisService.delete(key);

    }
}

import { Util } from "../util";
import { Gateway, GatewayDetail } from "../model/network";
import { ConfigService } from "./configService";
import { RedisService } from "./redisService";

export class GatewayService {
    /**
     * @summary execute gateway business
         *
         */

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
        let pos = '0';
        let items: GatewayDetail[] = [];
        while (true) {
            const [cursor, elements] = await this.redisService.scan(`/host/id/*`, pos, 10000, 'hash');
            pos = cursor;

            const pipeline = await this.redisService.multi();
            for (const key of elements) {
                await pipeline.hgetAll(key);
            }
            const gdetails = await pipeline.exec() as GatewayDetail[];
            //parse string values to numbers
            gdetails.forEach(x => {
                this.normalize(x);

            })
            items = items.concat(gdetails)
            if (!cursor || cursor == '0')
                break;

        }
        return items;
    }

    async getAliveById(id: string) {
        let key = `/host/id/${id}`;
        const isExists = await this.redisService.containsKey(key);
        if (!isExists) return null;
        const gatewayDetail = await this.redisService.hgetAll(key) as unknown as GatewayDetail;
        return this.normalize(gatewayDetail);
    }
}
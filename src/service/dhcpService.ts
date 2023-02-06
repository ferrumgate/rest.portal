import { logger } from "../common";
import { getNetworkByGatewayId } from "../api/commonApi";
import { ConfigService } from "./configService";
import { RedisService } from "./redisService";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { Util } from "../util";

/**
 * @summary a dhcp implementation
 */
export class DhcpService {

    lastUsedIps: Map<string, bigint> = new Map();
    lastUsedTrackId: number = 0;
    /**
     *
     */
    constructor(private config: ConfigService, private redis: RedisService) {


    }
    async getEmptyIp(gatewayId: string) {
        const network = await getNetworkByGatewayId(this.config, gatewayId);
        const clientCidr = network.clientNetwork;
        if (!clientCidr.includes('/')) {
            logger.error("config client network is not valid");
            throw new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodesInternal.ErrClientNetworkNotValid, "client network is not valid");
        }
        const parts = clientCidr.split('/');
        const range = Util.ipCidrToRange(parts[0], Number(parts[1]));
        const lastUsedIp = this.lastUsedIps.get(network.id);
        let start = lastUsedIp || Util.ipToBigInteger(range.start) + 1n;//for performance track last used ip
        let end = Util.ipToBigInteger(range.end);
        if (start >= end)// if all pool ips used, then start from beginning for search
            start = Util.ipToBigInteger(range.start);

        for (let s = start; s < end; s++) {
            const ip = Util.bigIntegerToIp(s);
            const isExists = await this.redis.containsKey(`/tunnel/ip/${ip}`);
            if (!isExists) {
                const added = await this.redis.setnx(`/tunnel/ip/${ip}`, 'reserved', 5 * 1000);
                if (added) {
                    this.lastUsedIps.set(network.id, s);
                    return { network: network, ip: s };
                }
            }
        }

        logger.fatal("tunnel ip pool is over");
        throw new RestfullException(500, ErrorCodes.ErrIpAssignFailed, ErrorCodesInternal.ErrIpPoolIsOver, 'ip pool is over');
    }
    async leaseIp(ip: string, key: string, leaseTime = 7 * 60 * 1000) {
        await this.redis.set(`/tunnel/ip/${ip}`, key, { ttl: leaseTime });
    }
    async releaseIp(ip: string) {
        await this.redis.delete(`/tunnel/ip/${ip}`);
    }
    async isIpExits(ip: string) {
        return await this.redis.containsKey(`/tunnel/ip/${ip}`);
    }
    async getIpValue(ip: string) {
        return await this.redis.get(`/tunnel/ip/${ip}`, false);
    }

    async getEmptyTrackId() {
        for (let i = this.lastUsedTrackId + 1; i < 4294967295; ++i) {
            const isExists = await this.redis.containsKey(`/tunnel/trackId/${i}`);
            if (!isExists)
                return {
                    trackId: i
                };
        }
        for (let i = 1; i < this.lastUsedTrackId; ++i) {
            const isExists = await this.redis.containsKey(`/tunnel/trackId/${i}`);
            if (!isExists) {
                const added = await this.redis.setnx(`/tunnel/trackId/${i}`, 'reserved', 5 * 1000);
                if (added) {
                    this.lastUsedTrackId = i;
                    return {
                        trackId: i
                    };
                }
            }
        }
        logger.fatal("tunnel track id pool is over");
        throw new RestfullException(500, ErrorCodes.ErrTrackIdAssignFailed, ErrorCodes.ErrTrackIdAssignFailed, 'track id pool is over');


    }
    async leaseTrackId(trackId: number, key: string, leaseTime = 7 * 60 * 1000) {
        await this.redis.set(`/tunnel/trackId/${trackId}`, key, { ttl: leaseTime });
    }

}
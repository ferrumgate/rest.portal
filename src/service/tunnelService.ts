import { User } from "../model/user";
import { logger } from "../common";
import { ErrorCodes, RestfullException } from "../restfullException";
import { ConfigService } from "./configService";
import { RedisService } from "./redisService";
import { Util } from "../util";


/**
 * @summary execute tunnel business, create tunnel related objects in redis,
 * find an ip 
 */
export class TunnelService {
    /**
     *
     */
    private _lastUsedIp: bigint = BigInt(0);
    private clientNetworkUsedList = '/clientNetwork/used';
    constructor(private config: ConfigService) {


    }
    get lastUsedIp() {
        return this._lastUsedIp;
    }
    async getEmptyIp(redisService: RedisService) {
        const network = await this.config.getClientNetwork();
        if (!network.includes('/')) {
            logger.error("config client network is not valid");
            throw new RestfullException(500, ErrorCodes.ErrInternalError, "client network is not valid");
        }
        const parts = network.split('/');
        const range = Util.ipCidrToRange(parts[0], Number(parts[1]));
        let start = this.lastUsedIp || Util.ipToBigInteger(range.start) + 1n;//for performance track last used ip
        let end = Util.ipToBigInteger(range.end);
        if (start >= end)// if all pool ips used, then start from beginning for search
            start = Util.ipToBigInteger(range.start);




        for (let s = start; s < end; s++) {
            const ip = Util.bigIntegerToIp(s);
            const isExists = await redisService.sismember(this.clientNetworkUsedList, ip);
            if (!isExists) return s;
        }

        logger.fatal("client ip pool is over");
        throw new RestfullException(500, ErrorCodes.ErrIpAssignFailed, 'ip pool is over');
    }
    async createTunnel(user: User, redisService: RedisService, session: string) {
        const key = `/session/${session}`;
        const ses = await redisService.hgetAll(key) as { id?: string, clientIp?: string, tun?: string, authenticatedTime?: string };
        if (!ses || !ses.id || !ses.clientIp) {
            logger.error(`session not found or some fields are absent => ${ses || ''}`);
            throw new RestfullException(401, ErrorCodes.ErrSecureTunnelFailed, 'secure tunnel failed');
        }

        //security check
        if (!ses.authenticatedTime) {
            //peer ip must be set before 
            const ip = await this.getEmptyIp(redisService);
            const ipstr = Util.bigIntegerToIp(ip);
            this._lastUsedIp = ip;
            await redisService.hset(key, { assignedClientIp: ipstr, userId: user.id });
            await redisService.sadd(this.clientNetworkUsedList, Util.bigIntegerToIp(ip));
            //all client checking will be over this ip
            //client will set this ip to its interface
            // then will confirm ok
            // and system will prepare additional network settings
            await redisService.set(`/client/${ipstr}`, session, { ttl: 5 * 60 * 1000 });


            const authenticationChannel = `/session/authentication/${session}`;
            //send every thing ok message to waiting client to finish tunneling
            await redisService.publish(authenticationChannel, 'ok:');
            await redisService.hset(key, { authenticatedTime: new Date().toISOString() });
            await redisService.expire(key, 5 * 60);
        }



    }
}
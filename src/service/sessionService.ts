import { User } from "../model/user";
import { logger } from "../common";
import { ErrorCodes, RestfullException } from "../restfullException";
import { ConfigService } from "./configService";
import { RedisService } from "./redisService";
import { Util } from "../util";
import { Tunnel } from "../model/tunnel";
import { HelperService } from "./helperService";
import { getNetworkByGatewayId } from "../api/commonApi";
import { AuthSession } from "../model/authSession";


/**
 * @summary execute tunnel business, create tunnel related objects in redis,
 * find an ip 
 */
export class SessionService {
    /**
     *
     */

    lastUsedIps: Map<string, bigint> = new Map();
    lastUsedTrackId: number = 0;
    constructor(private config: ConfigService, private redisService: RedisService) {


    }
    async createSession(user: User, is2FA: boolean, clientIp: string, authSource: string) {
        const session: AuthSession = {
            id: Util.randomNumberString(64),
            insertDate: new Date().toISOString(),
            ip: clientIp, is2FA: is2FA,
            lastSeen: new Date().toISOString(),
            source: authSource || 'unknown',
            userId: user.id,
            username: user.username,

        }
        const sidkey = `/session/id/${session.id}`;
        await this.redisService.hset(sidkey, session);
        await this.setExpire(session.id);
        return session;
    }
    async createFakeSession(user: User, is2FA: boolean, clientIp: string, authSource: string) {
        const session: AuthSession = {
            id: Util.randomNumberString(64),
            insertDate: new Date().toISOString(),
            ip: clientIp, is2FA: is2FA,
            lastSeen: new Date().toISOString(),
            source: authSource || 'unknown',
            userId: user.id,
            username: user.username,

        }
        return session;
    }

    async getSession(id: string): Promise<AuthSession | undefined> {
        const sidkey = `/session/id/${id}`;
        const authSession = await this.redisService.hgetAll(sidkey) as unknown as AuthSession;

        if (Object.keys(authSession).length) {
            authSession.is2FA = Util.convertToBoolean(authSession.is2FA);

            return authSession;
        }
        return undefined;
    }
    async setSession(id: string, obj: any) {
        const sidkey = `/session/id/${id}`;

        await this.redisService.hset(sidkey, obj);
    }
    async setExpire(id: string) {
        const sidkey = `/session/id/${id}`;
        await this.redisService.expire(sidkey, 5 * 60 * 1000);
        const sidtunkey = `/session/tunnel/${id}`;
        await this.redisService.expire(sidtunkey, 5 * 60 * 1000);
    }
    async deleteSession(id: string) {
        const sidkey = `/session/id/${id}`;
        await this.redisService.delete(sidkey);
        const sidtunkey = `/session/tunnel/${id}`;
        await this.redisService.delete(sidtunkey);

    }

    async addTunnel(id: string, tunnelId: string) {
        const sidtunkey = `/session/tunnel/${id}`;
        await this.redisService.sadd(sidtunkey, tunnelId);
        await this.redisService.expire(sidtunkey, 5 * 60 * 1000);

    }
    async removeTunnel(id: string, tunnelId: string) {
        const sidtunkey = `/session/tunnel/${id}`;
        await this.redisService.sremove(sidtunkey, tunnelId);
        await this.redisService.expire(sidtunkey, 5 * 60 * 1000);
    }
}

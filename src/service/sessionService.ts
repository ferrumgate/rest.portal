import { User } from "../model/user";
import { logger } from "../common";
import { ErrorCodes, RestfullException } from "../restfullException";
import { ConfigService } from "./configService";
import { RedisPipelineService, RedisService } from "./redisService";
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
    async createSession(user: User, is2FA: boolean, clientIp: string, authSource: string,
        countryCode?: string, countryName?: string, isProxyIp?: boolean, isHostingIp?: boolean, isCrawlerIp?: boolean) {
        const session: AuthSession = {
            id: Util.randomNumberString(64),
            insertDate: new Date().toISOString(),
            ip: clientIp, is2FA: is2FA,
            lastSeen: new Date().toISOString(),
            source: authSource || 'unknown',
            userId: user.id,
            username: user.username,
            countryCode: countryCode,
            countryName: countryName,
            isProxyIp: isProxyIp,
            isCrawlerIp: isCrawlerIp,
            isHostingIp: isHostingIp
        }
        const sidkey = `/session/id/${session.id}`;
        const pipeline = await this.redisService.multi()
        await pipeline.hset(sidkey, session);
        await this.setExpire(session.id, pipeline);
        await pipeline.exec();
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
    async createEmptySession(clientIp: string) {
        const session: AuthSession = {
            id: Util.randomNumberString(64),
            insertDate: new Date().toISOString(),
            ip: clientIp, is2FA: false,
            lastSeen: new Date().toISOString(),
            source: 'unknown',
            userId: 'unknown',
            username: 'unknown',

        }
        return session;
    }

    async getSession(id: string): Promise<AuthSession | undefined> {
        const sidkey = `/session/id/${id}`;
        const authSession = await this.redisService.hgetAll(sidkey) as unknown as AuthSession;

        if (Object.keys(authSession).length) {
            authSession.is2FA = Util.convertToBoolean(authSession.is2FA);
            authSession.isCrawlerIp = Util.convertToBoolean(authSession.isCrawlerIp);
            authSession.isProxyIp = Util.convertToBoolean(authSession.isProxyIp);
            authSession.isHostingIp = Util.convertToBoolean(authSession.isHostingIp);

            return authSession;
        }
        return undefined;
    }
    async setSession(id: string, obj: any) {
        const sidkey = `/session/id/${id}`;
        await this.redisService.hset(sidkey, obj);
    }
    async setExpire(id: string, pipeline?: RedisPipelineService) {
        const sidkey = `/session/id/${id}`;
        const sidtunkey = `/session/tunnel/${id}`;
        if (pipeline) {
            await pipeline.expire(sidkey, 5 * 60 * 1000);
            await pipeline.expire(sidtunkey, 5 * 60 * 1000);
        } else {

            await this.redisService.expire(sidkey, 5 * 60 * 1000);
            await this.redisService.expire(sidtunkey, 5 * 60 * 1000);
        }

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

    async getSessionKeys() {
        return await this.redisService.getAllKeys('/session/id/*', 'hash');
    }

    async getAllValidSessions(cont: () => boolean) {
        let page = 0;
        let pos = '0';
        let retList: AuthSession[] = [];
        while (cont) {
            const [cursor, results] = await this.redisService.scan('/session/id/*', pos, 10000, 'hash');
            pos = cursor;
            const pipeline = await this.redisService.multi();
            for (const key of results) {
                await pipeline.hgetAll(key);
            }
            const sessions = await pipeline.exec() as AuthSession[];
            const validSessions = sessions.filter(session => {
                session.is2FA = Util.convertToBoolean(session.is2FA);
                session.isCrawlerIp = Util.convertToBoolean(session.isCrawlerIp);
                session.isProxyIp = Util.convertToBoolean(session.isProxyIp);
                session.isHostingIp = Util.convertToBoolean(session.isHostingIp);
                return true;
            })
            validSessions.forEach(x => {
                if (x.id) {
                    retList.push(x);
                }
            });

            if (!cursor || cursor == '0')
                break;
            page++;
        }
        return retList;
    }
}

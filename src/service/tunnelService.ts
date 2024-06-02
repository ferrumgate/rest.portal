import { getNetworkByGatewayId } from "../api/commonApi";
import { logger } from "../common";
import { AuthSession } from "../model/authSession";
import { Tunnel } from "../model/tunnel";
import { User } from "../model/user";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { RedisService } from "../service/redisService";
import { Util } from "../util";
import { ConfigService } from "./configService";
import { DhcpService } from "./dhcpService";
import { HelperService } from "./helperService";


/**
 * @summary execute tunnel business, create tunnel related objects in redis,
 * find an ip 
 */
export class TunnelService {
    /**
     *
     */

    //lastUsedIps: Map<string, bigint> = new Map();
    //lastUsedTrackId: number = 0;
    constructor(private config: ConfigService, private redisService: RedisService, private dhcp: DhcpService) {


    }
    /* async getEmptyTrackId() {
        for (let i = this.lastUsedTrackId + 1; i < 4294967295; ++i) {
            const isExists = await this.redisService.containsKey(`/tunnel/trackId/${i}`);
            if (!isExists)
                return {
                    trackId: i
                };
        }
        for (let i = 1; i < this.lastUsedTrackId; ++i) {
            const isExists = await this.redisService.containsKey(`/tunnel/trackId/${i}`);
            if (!isExists)
                return {
                    trackId: i
                };
        }
        logger.fatal("tunnel track id pool is over");
        throw new RestfullException(500, ErrorCodes.ErrTrackIdAssignFailed, ErrorCodes.ErrTrackIdAssignFailed, 'track id pool is over');


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
            const isExists = await this.redisService.containsKey(`/tunnel/ip/${ip}`);
            if (!isExists) return { network: network, ip: s };
        }

        logger.fatal("tunnel ip pool is over");
        throw new RestfullException(500, ErrorCodes.ErrIpAssignFailed, ErrorCodesInternal.ErrIpPoolIsOver, 'ip pool is over');
    } */
    async getNetwork(tunnel: Tunnel) {
        const network = getNetworkByGatewayId(this.config, tunnel.gatewayId);
        return network;
    }
    async getTunnel(tunnelKey: string) {
        const key = `/tunnel/id/${tunnelKey}`;
        const tunnel = await this.redisService.hgetAll(key) as unknown as Tunnel;
        if (Object.keys(tunnel)) {
            tunnel.is2FA = Util.convertToBoolean(tunnel.is2FA);
            tunnel.trackId = Util.convertToNumber(tunnel.trackId);
            return tunnel;
        }
        return undefined;
    }
    async getTunnelKeyFromClientIp(clientIp: string) {
        return await this.redisService.get(`/tunnel/ip/${clientIp}`, false) as string | undefined;
    }

    async getTunnelKeyFromTrackId(trackId: string | number) {
        return await this.redisService.get(`/tunnel/trackId/${trackId.toString()}`, false) as string | undefined;
    }
    async createTunnel(user: User, tunnelKey: string, session: AuthSession) {
        const key = `/tunnel/id/${tunnelKey}`;
        const tunnel = await this.getTunnel(tunnelKey);
        if (!tunnel || !tunnel.id || !tunnel.clientIp) {
            logger.error(`tunnel not found or some fields are absent => ${tunnel || ''}`);
            throw new RestfullException(401, ErrorCodes.ErrTunnelFailed, ErrorCodesInternal.ErrTunnelNotFoundOrNotValid, 'secure tunnel failed');
        }

        //security check
        if (!tunnel.authenticatedTime) {
            //peer ip must be set before 
            //10 second timeout
            const tenSecondMilisecond = 10 * 1000;
            const startMS = Util.milisecond();

            const { network, ip } = await this.dhcp.getEmptyIp(tunnel.gatewayId || '');
            const { trackId } = await this.dhcp.getEmptyTrackId();
            const ipstr = Util.bigIntegerToIp(ip);
            //this.lastUsedIps.set(network.id, ip);
            //this.lastUsedTrackId = trackId;
            const pipeline = await this.redisService.multi();
            await pipeline.hset(key, { assignedClientIp: ipstr, trackId: trackId, userId: user.id, sessionId: session.id, is2FA: session.is2FA });
            await pipeline.expire(key, 5 * 60 * 1000);
            await pipeline.exec();
            //await redisService.sadd(this.clientNetworkUsedList, Util.bigIntegerToIp(ip));
            //all client checking will be over this ip
            //client will set this ip to its interface
            // then will confirm ok
            // and system will prepare additional network settings
            await this.dhcp.leaseIp(ipstr, tunnelKey);
            await this.dhcp.leaseTrackId(trackId, tunnelKey);


            await this.redisService.hset(key, { authenticatedTime: new Date().toISOString() });
            const gateNetwork = await this.getNetwork(tunnel);

            await this.redisService.hset(key, { serviceNetwork: gateNetwork.serviceNetwork });
            await this.redisService.expire(key, 5 * 60 * 1000);


            const now = Util.milisecond();
            const diff = now - startMS;
            if (diff > tenSecondMilisecond)
                throw new RestfullException(408, ErrorCodes.ErrTimeout, ErrorCodes.ErrTimeout, `confirm took much then 10 second  value ms:${diff}`)

            // at the end
            //send every thing ok message to waiting client to finish tunneling
            const authenticationChannel = `/tunnel/authentication/${tunnelKey}`;
            logger.info(`authenticating tunnel tunnelKey: ${tunnelKey}`);
            //there must be a better way to do this
            // when cloud version activated, there is a race condition
            for (let i = 0; i < 5; i++) {
                await this.redisService.publish(authenticationChannel, 'ok:');
                await Util.sleep(250);//wait for sync with client
            }


        } else {
            logger.warn(`tunnel authenticated time is not valid tunnelKey: ${tunnelKey}`)
        }

        return await this.redisService.hgetAll(key) as unknown as Tunnel;


    }

    /**
     * @summary renew assigned ip
     * @param tunnelKey 
     * @param redisService 
     * @returns 
     */
    async renewIp(tunnelKey: string) {
        const key = `/tunnel/id/${tunnelKey}`;
        const tunnel = await this.redisService.hgetAll(key) as unknown as Tunnel;
        HelperService.isValidTunnel(tunnel);
        const tmp = tunnel.assignedClientIp;
        //peer ip must be set before 
        const { network, ip } = await this.dhcp.getEmptyIp(tunnel.gatewayId || '');
        const ipstr = Util.bigIntegerToIp(ip);
        //this.lastUsedIps.set(network.id, ip);
        await this.redisService.hset(key, { assignedClientIp: ipstr });
        await this.dhcp.leaseIp(ipstr, tunnelKey);
        if (tmp)
            await this.dhcp.releaseIp(tmp);
        await this.redisService.expire(`/gateway/${tunnel.gatewayId}/tun/${tunnel.tun}`, 5 * 60 * 1000);
        await this.redisService.expire(key, 5 * 60 * 1000);
        return await this.redisService.hgetAll(key) as unknown as Tunnel;

    }

    /**
     * @summary confirm tunnel
     * @param tunnelKey 
     * @param redisService 
     */
    async confirm(tunnelKey: string) {
        const key = `/tunnel/id/${tunnelKey}`;
        const tunnel = await this.redisService.hgetAll(key) as unknown as Tunnel;
        HelperService.isValidTunnel(tunnel);
        await this.redisService.set(`/gateway/${tunnel.gatewayId}/tun/${tunnel.tun}`, tunnelKey, { ttl: 5 * 60 * 1000 });
        // add to a list
        //await this.redisService.sadd(`/tunnel/configure/${tunnel.gatewayId}`, tunnel.id || '');
        //await this.redisService.expire(`/tunnel/configure/${tunnel.gatewayId}`, 5 * 60 * 1000);
        // and publish to listener for configuring all network settings to the destination gateway
        //await this.redisService.publish(`/tunnel/configure/${tunnel.gatewayId}`, tunnel.id);
    }

    /**
     * @summary every client sends I am alive request
     * @param tunnelKey 
     * @param redisService 
     */
    async alive(tunnelKey: string) {
        const key = `/tunnel/id/${tunnelKey}`;
        const tunnel = await this.redisService.hgetAll(key) as unknown as Tunnel;
        HelperService.isValidTunnel(tunnel);
        //3 important keys for system
        await this.redisService.expire(key, 5 * 60 * 1000);
        // at least 5 minutes, because we must not use same ip, a little bit more security 
        await this.redisService.expire(`/tunnel/ip/${tunnel.assignedClientIp}`, 7 * 60 * 1000);
        await this.redisService.expire(`/tunnel/trackId/${tunnel.trackId}`, 7 * 60 * 1000);
        await this.redisService.expire(`/gateway/${tunnel.gatewayId}/tun/${tunnel.tun}`, 5 * 60 * 1000);

    }

    async getTunnelKeys() {
        return await this.redisService.getAllKeys('/tunnel/id/*', 'hash');
    }

    async getAllValidTunnels(cont: () => boolean) {
        let page = 0;
        let pos = '0';
        let retList: Tunnel[] = [];
        while (cont) {
            const [cursor, results] = await this.redisService.scan('/tunnel/id/*', pos, 10000, 'hash');
            pos = cursor;
            const pipeline = await this.redisService.pipeline();
            for (const key of results) {
                await pipeline.hgetAll(key);
            }
            const tunnels = await pipeline.exec() as Tunnel[];
            const validTunnels = tunnels.filter(tunnel => {
                tunnel.is2FA = Util.convertToBoolean(tunnel.is2FA);
                tunnel.trackId = Util.convertToNumber(tunnel.trackId);
                return HelperService.isValidTunnelNoException(tunnel) ? false : true;
            })
            validTunnels.forEach(x => {
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
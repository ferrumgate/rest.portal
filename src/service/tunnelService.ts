import { User } from "../model/user";
import { logger } from "../common";
import { ErrorCodes, RestfullException } from "../restfullException";
import { ConfigService } from "./configService";
import { RedisService } from "./redisService";
import { Util } from "../util";
import { Tunnel } from "../model/tunnel";
import { HelperService } from "./helperService";
import { getNetworkByHostId } from "../api/commonApi";


/**
 * @summary execute tunnel business, create tunnel related objects in redis,
 * find an ip 
 */
export class TunnelService {
    /**
     *
     */

    lastUsedIps: Map<string, bigint> = new Map();
    constructor(private config: ConfigService, private redisService: RedisService) {


    }

    async getEmptyIp(hostId: string) {
        const network = await getNetworkByHostId(this.config, hostId);
        const clientCidr = network.clientNetwork;
        if (!clientCidr.includes('/')) {
            logger.error("config client network is not valid");
            throw new RestfullException(500, ErrorCodes.ErrInternalError, "client network is not valid");
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
            const isExists = await this.redisService.containsKey(`/client/${ip}`);
            if (!isExists) return { network: network, ip: s };
        }

        logger.fatal("client ip pool is over");
        throw new RestfullException(500, ErrorCodes.ErrIpAssignFailed, 'ip pool is over');
    }
    async getServiceNetwork(tunnel: Tunnel) {
        const network = getNetworkByHostId(this.config, tunnel.hostId);
        return network;
    }
    async getTunnel(tunnelKey: string) {
        const key = `/tunnel/${tunnelKey}`;
        const tunnel = await this.redisService.hgetAll(key) as unknown as Tunnel;

        tunnel.is2FA = Util.convertToBoolean(tunnel.is2FA);
        tunnel.isPAM = Util.convertToBoolean(tunnel.isPAM);
        return tunnel;
    }
    async getTunnelKey(clientIp: string) {
        return await this.redisService.get(`/client/${clientIp}`, false) as string | undefined;
    }
    async createTunnel(user: User, tunnelKey: string) {
        const key = `/tunnel/${tunnelKey}`;
        const tunnel = await this.getTunnel(tunnelKey);
        if (!tunnel || !tunnel.id || !tunnel.clientIp) {
            logger.error(`tunnel not found or some fields are absent => ${tunnel || ''}`);
            throw new RestfullException(401, ErrorCodes.ErrSecureTunnelFailed, 'secure tunnel failed');
        }

        //security check
        if (!tunnel.authenticatedTime) {
            //peer ip must be set before 
            const { network, ip } = await this.getEmptyIp(tunnel.hostId || '');
            const ipstr = Util.bigIntegerToIp(ip);
            this.lastUsedIps.set(network.id, ip);
            await this.redisService.hset(key, { assignedClientIp: ipstr, userId: user.id });
            //await redisService.sadd(this.clientNetworkUsedList, Util.bigIntegerToIp(ip));
            //all client checking will be over this ip
            //client will set this ip to its interface
            // then will confirm ok
            // and system will prepare additional network settings
            await this.redisService.set(`/client/${ipstr}`, tunnelKey, { ttl: 5 * 60 * 1000 });




            await this.redisService.hset(key, { authenticatedTime: new Date().toISOString() });
            await this.redisService.hset(key, { serviceNetwork: await this.getServiceNetwork(tunnel) });
            await this.redisService.expire(key, 5 * 60 * 1000);
            // at the end
            //send every thing ok message to waiting client to finish tunneling
            const authenticationChannel = `/tunnel/authentication/${tunnelKey}`;
            await this.redisService.publish(authenticationChannel, 'ok:');
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
        const key = `/tunnel/${tunnelKey}`;
        const tunnel = await this.redisService.hgetAll(key) as unknown as Tunnel;
        HelperService.isValidTunnel(tunnel);
        const tmp = tunnel.assignedClientIp;
        //peer ip must be set before 
        const { network, ip } = await this.getEmptyIp(tunnel.hostId || '');
        const ipstr = Util.bigIntegerToIp(ip);
        this.lastUsedIps.set(network.id, ip);
        await this.redisService.hset(key, { assignedClientIp: ipstr });
        await this.redisService.set(`/client/${ipstr}`, tunnelKey, { ttl: 5 * 60 * 1000 });
        if (tmp)
            await this.redisService.delete(`/client/${tmp}`);
        await this.redisService.expire(`/host/${tunnel.hostId}/tun/${tunnel.tun}`, 5 * 60 * 1000);
        await this.redisService.expire(key, 5 * 60 * 1000);
        return await this.redisService.hgetAll(key) as unknown as Tunnel;

    }

    /**
     * @summary confirm tunnel
     * @param tunnelKey 
     * @param redisService 
     */
    async confirm(tunnelKey: string) {
        const key = `/tunnel/${tunnelKey}`;
        const tunnel = await this.redisService.hgetAll(key) as unknown as Tunnel;
        HelperService.isValidTunnel(tunnel);
        await this.redisService.set(`/host/${tunnel.hostId}/tun/${tunnel.tun}`, tunnelKey, { ttl: 5 * 60 * 1000 });
        // add to a list
        await this.redisService.sadd(`/tunnel/configure/${tunnel.hostId}`, tunnel.id || '');
        await this.redisService.expire(`/tunnel/configure/${tunnel.hostId}`, 3 * 60 * 1000);
        // and publish to listener for configuring all network settings to the destination host
        await this.redisService.publish(`/tunnel/configure/${tunnel.hostId}`, tunnel.id);
    }

    /**
     * @summary every client sends I am alive request
     * @param tunnelKey 
     * @param redisService 
     */
    async alive(tunnelKey: string) {
        const key = `/tunnel/${tunnelKey}`;
        const tunnel = await this.redisService.hgetAll(key) as unknown as Tunnel;
        HelperService.isValidTunnel(tunnel);
        //3 important keys for system
        await this.redisService.expire(key, 3 * 60 * 1000);
        // at least 5 minutes, because we must not use same ip, a little bit more security 
        await this.redisService.expire(`/client/${tunnel.assignedClientIp}`, 5 * 60 * 1000);
        await this.redisService.expire(`/host/${tunnel.hostId}/tun/${tunnel.tun}`, 3 * 60 * 1000);

    }
}
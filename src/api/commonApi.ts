import { logger } from "../common";
import { ErrorCodes, RestfullException } from "../restfullException";
import { ConfigService } from "../service/configService";

/**
 * @summary get network by host id and also check is it is joined and active
 * @param configService 
 * @param hostId 
 */
export async function getNetworkByHostId(configService: ConfigService, hostId?: string) {
    if (!hostId) {
        logger.error(`host id is empty`);
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'no gateway found');
    }
    const gateway = await configService.getGateway(hostId);
    if (!gateway) {
        logger.error(`no gateway found ${hostId}`)
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'no gateway found');
    }
    if (!gateway.isActive || !gateway.isJoined) {
        logger.error(`gateway is not active or joined ${hostId}`)
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'gateway not joined or active');
    }
    if (!gateway.networkId) {
        logger.error(`gateway has no network ${hostId}`);
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'gateway has no network');
    }
    const network = await configService.getNetwork(gateway.networkId);
    if (!network) {
        logger.error(`no network found for host: ${hostId} network: ${gateway.networkId}`);
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'gateway has no network');
    }
    return network;

}
import { User } from "../model/user";
import { AppService } from "../service/appService";
import { logger } from "../common";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { ConfigService } from "../service/configService";
import { RBACDefault } from "../model/rbac";
import { saveActivityError } from "./auth/commonAuth";

/**
 * @summary get network by gateway id and also check is it is joined and active
 * @param configService 
 * @param gatewayId 
 */
export async function getNetworkByGatewayId(configService: ConfigService, gatewayId?: string) {
    if (!gatewayId) {
        logger.error(`gateway id is empty`);
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, 'no gateway found');
    }
    const gateway = await configService.getGateway(gatewayId);
    if (!gateway) {
        logger.error(`no gateway found ${gatewayId}`)
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrGatewayNotFound, 'no gateway found');
    }

    //this check is important because of security
    if (!gateway.isEnabled) {
        logger.error(`gateway is not active or joined ${gatewayId}`)
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrGatewayNotValid, 'gateway not joined or active');
    }
    if (!gateway.networkId) {
        logger.error(`gateway has no network ${gatewayId}`);
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrGatewayNotValid, 'gateway has no network');
    }
    const network = await configService.getNetwork(gateway.networkId);
    if (!network) {
        logger.error(`no network found for gateway: ${gatewayId} network: ${gateway.networkId}`);
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrNetworkNotFound, 'gateway has no network');
    }
    return network;

}

/**
 * @summary authorize system according to rights
 * @param req 
 * @param res 
 * @param next 
 * @param rights 
 */
export async function authorize(req: any, res: any, next: any, rights: string[]) {
    try {
        logger.info(`authorizing with for rights ${rights.join(',')}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const user = req.currentUser as User;
        if (!user)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrUserNotFound, 'not authorized');


        const roles = await configService.getUserRoles(user);
        let founded = false;
        for (const role of roles) {
            if (role.rights) {
                for (const right of role.rights) {
                    if (rights.find(y => y == right.id)) {
                        founded = true;
                        break;
                    }
                }
            }
            if (founded) break;

        }
        if (founded)
            next();
        else
            throw new RestfullException(401, ErrorCodes.ErrNotEnoughRight, ErrorCodes.ErrNotEnoughRight, `not authorized,not enough right`);
    } catch (err) {
        await saveActivityError(req, 'authorize', err);
        throw err;
    }

}

export async function authorizeAsAdmin(req: any, res: any, next: any) {
    await authorize(req, res, next, [RBACDefault.rightAdmin.id]);
}

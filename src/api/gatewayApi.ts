import express from "express";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AuthSession } from "../model/authSession";
import { Gateway, GatewayDetail, cloneGateway } from "../model/network";
import { User } from "../model/user";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { AppService } from "../service/appService";
import { ConfigService } from "../service/configService";
import { GatewayService } from "../service/gatewayService";
import { Util } from "../util";
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import { authorizeAsAdmin } from "./commonApi";


/////////////////////////////////  gateway //////////////////////////////////
export const routerGatewayAuthenticated = express.Router();



routerGatewayAuthenticated.get('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting gateway with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const gateway = await configService.getGateway(id);
        if (!gateway) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrGatewayNotFound, 'no gateway');


        return res.status(200).json(gateway);

    }))

function gatewayDetailToGateway(x: GatewayDetail) {
    let gateway: Gateway = {
        id: x.id,
        name: x.hostname || 'unknown',
        insertDate: new Date().toISOString(),
        labels: [], updateDate: new Date().toISOString(),
        isEnabled: true,
        nodeId: x.nodeId

    }
    return gateway;
}

export async function getNotJoinedGateways(configService: ConfigService, gatewayService: GatewayService) {
    const aliveGateways = await gatewayService.getAllAlive();
    let items: Gateway[] = [];
    const gateways = await configService.getGatewaysByNetworkId('');
    items = items.concat(gateways);
    //create a map for fast search
    let fastMap = new Map();
    items.forEach(x => fastMap.set(x.id, x.id));
    // alive items newly seen
    const notInList = aliveGateways.filter(x => !fastMap.get(x.id));
    notInList.forEach(x => {
        items.push(gatewayDetailToGateway(x));
    })
    return items;
}

routerGatewayAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        const ids = req.query.ids as string;
        const notJoined = req.query.notJoined;
        logger.info(`query gateway`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const gatewayService = appService.gatewayService;
        let items: Gateway[] = [];

        if (search) {
            const gateways = await configService.getGatewaysBy(search.toLowerCase());
            items = items.concat(gateways);

        } else
            if (ids) {
                const parts = ids.split(',');
                for (const id of parts) {
                    const gateway = await configService.getGateway(id);
                    if (gateway)
                        items.push(gateway);
                }

            } else
                if (notJoined) {
                    //find alive items and add them as real         
                    items = await getNotJoinedGateways(configService, gatewayService);


                } else {
                    //find alive items and add them as real         
                    const aliveGateways = await gatewayService.getAllAlive();
                    items = await configService.getGatewaysAll();
                    //create a map for fast search
                    let fastMap = new Map();
                    items.forEach(x => fastMap.set(x.id, x.id));
                    // alive items newly seen
                    const notInList = aliveGateways.filter(x => !fastMap.get(x.id));
                    notInList.forEach(x => {
                        items.push(gatewayDetailToGateway(x));
                    })
                }
        return res.status(200).json({
            items: items
        });

    }))


routerGatewayAuthenticated.delete('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`delete gateway with id: ${id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const gatewayService = appService.gatewayService;

        const gateway = await configService.getGateway(id);
        const gatewayAlive = await gatewayService.getAliveById(id);
        if (!gateway && !gatewayAlive) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrGatewayNotFound, 'no gateway');

        await gatewayService.deleteAliveById(id);
        if (gateway) {
            const { before } = await configService.deleteGateway(gateway.id);
            await auditService.logDeleteGateway(currentSession, currentUser, before);
        }

        return res.status(200).json({});

    }))


routerGatewayAuthenticated.put('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as Gateway;
        logger.info(`changing gateway settings for ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const gatewayService = appService.gatewayService;
        const auditService = appService.auditService;


        await inputService.checkNotEmpty(input.id);
        const gateway = await configService.getGateway(input.id);
        const notRegistered = await gatewayService.getAliveById(input.id);
        if (!gateway && !notRegistered) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrGatewayNotFound, 'no gateway');


        input.name = input.name || 'gateway';
        input.labels = input.labels || [];
        input.nodeId = notRegistered?.nodeId || input.nodeId;
        const safe = cloneGateway(input);

        const { before, after } = await configService.saveGateway(safe);
        await auditService.logSaveGateway(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerGatewayAuthenticated.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new gateway`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const input = req.body as Gateway;
        input.id = Util.randomNumberString(16);

        input.name = input.name || 'gateway';
        input.labels = input.labels || [];
        const safe = cloneGateway(input)

        const { before, after } = await configService.saveGateway(safe);
        await auditService.logSaveGateway(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))


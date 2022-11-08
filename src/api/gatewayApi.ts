import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import passport from "passport";
import { ConfigService } from "../service/configService";
import { RBACDefault } from "../model/rbac";
import { authorize, authorizeAsAdmin } from "./commonApi";
import { cloneGateway, Gateway, GatewayDetail, Network } from "../model/network";


/////////////////////////////////  gateway //////////////////////////////////
export const routerGatewayAuthenticated = express.Router();



routerGatewayAuthenticated.get('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting gateway with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const gateway = await configService.getGateway(id);
        if (!gateway) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no gateway');


        return res.status(200).json(gateway);

    }))

function gatewayDetailToGateway(x: GatewayDetail) {
    let gateway: Gateway = {
        id: x.id,
        name: x.hostname || 'unknown',
        insertDate: new Date().toISOString(),
        labels: [], updateDate: new Date().toISOString(),
        isEnabled: true

    }
    return gateway;
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

        //find alive items and add them as real         
        const aliveGateways = await gatewayService.getAllAlive();



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


                } else {
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
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`delete gateway with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const gateway = await configService.getGateway(id);
        if (!gateway) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no gateway');

        await configService.deleteGateway(gateway.id);
        //TODO audit
        return res.status(200).json({});

    }))



routerGatewayAuthenticated.put('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as Gateway;
        logger.info(`changing gateway settings for ${input.id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const gatewayService = appService.gatewayService;

        await inputService.checkNotEmpty(input.id);
        const gateway = await configService.getGateway(input.id);
        const notRegistered = await gatewayService.getAliveById(input.id);
        if (!gateway && !notRegistered) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no gateway');


        input.name = input.name || 'gateway';
        input.labels = input.labels || [];
        const safe = cloneGateway(input);
        await configService.saveGateway(safe);
        // TODO audit here
        return res.status(200).json(safe);

    }))

routerGatewayAuthenticated.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new gateway`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        const input = req.body as Gateway;
        input.id = Util.randomNumberString(16);


        input.name = input.name || 'gateway';
        input.labels = input.labels || [];
        const safe = cloneGateway(input)
        await configService.saveGateway(safe);
        //TODO audit
        return res.status(200).json(safe);

    }))





import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportInit } from "./auth/passportInit";
import passport from "passport";
import { ConfigService } from "../service/configService";
import { RBACDefault } from "../model/rbac";
import { authorize, authorizeAsAdmin } from "./commonApi";
import { Gateway, Network } from "../model/network";


/////////////////////////////////  gateway //////////////////////////////////
export const routerGatewayAuthenticated = express.Router();



routerGatewayAuthenticated.get('/:id',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
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

routerGatewayAuthenticated.delete('/:id',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
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
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as Gateway;
        logger.info(`changing gateway settings for ${input.id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        const gateway = await configService.getGateway(input.id);
        if (!gateway) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no gateway');
        await inputService.checkNotEmpty(gateway.id);

        input.name = input.name || 'gateway';
        input.labels = input.labels || [];
        await configService.setGateway(gateway);
        // TODO audit here
        return res.status(200).json(input);

    }))

routerGatewayAuthenticated.post('/',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
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
        await configService.setGateway(input);
        //TODO audit
        return res.status(200).json({});

    }))

routerGatewayAuthenticated.get('/',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.search;
        const ids = req.ids as string;
        const notJoined = req.notJoined;
        logger.info(`configuring system for startup`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        let items: Gateway[] = [];
        if (search) {
            const networks = await configService.getGatewaysBySearch(search.toLowerCase());
            items = items.concat(networks);

        } else
            if (ids) {
                const parts = ids.split(',');
                for (const id of parts) {
                    const network = await configService.getGateway(id);
                    if (network)
                        items.push(network);
                }

            } else
                if (notJoined) {
                    const networks = await configService.getGatewaysByNetworkId('');
                    items = items.concat(networks);
                }
        return res.status(200).json(items);

    }))



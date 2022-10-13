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
import { cloneGateway, Gateway, Network } from "../model/network";


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

routerGatewayAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        const ids = req.query.ids as string;
        const notJoined = req.query.notJoined;
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
                } else
                    items = await configService.getGatewaysAll();
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

        await inputService.checkNotEmpty(input.id);
        const gateway = await configService.getGateway(input.id);
        if (!gateway) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no gateway');


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





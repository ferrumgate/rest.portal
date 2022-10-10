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
import { Network } from "../model/network";


/////////////////////////////////  network //////////////////////////////////
export const routerNetworkAuthenticated = express.Router();





routerNetworkAuthenticated.get('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting network with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const network = await configService.getNetwork(id);
        if (!network) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no network');

        //const gateways = await configService.getGatewaysByNetworkId(network.id);

        return res.status(200).json(network);

    }))

routerNetworkAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        const ids = req.query.ids as string;
        logger.info(`configuring system for startup`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        let items: Network[] = [];
        if (search) {
            const networks = await configService.getNetworksBySearch(search.toLowerCase());
            items = items.concat(networks);

        } else
            if (ids) {
                const parts = ids.split(',');
                for (const id of parts) {
                    const network = await configService.getNetwork(id);
                    if (network)
                        items.push(network);
                }

            } else
                items = await configService.getNetworksAll();

        return res.status(200).json({ items: items });

    }))

routerNetworkAuthenticated.delete('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`delete network with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const network = await configService.getNetwork(id);
        if (!network) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no network');

        await configService.deleteNetwork(network.id);
        //TODO audit
        return res.status(200).json({});

    }))

function copyNetwork(net: Network): Network {
    return {
        id: net.id, clientNetwork: net.clientNetwork, labels: net.labels, name: net.name, serviceNetwork: net.serviceNetwork
    }
}

routerNetworkAuthenticated.put('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as Network;
        logger.info(`changing network settings for ${input.id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        await inputService.checkNotEmpty(input.id);
        const network = await configService.getNetwork(input.id);
        if (!network) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no network');

        await inputService.checkCidr(input.clientNetwork);
        await inputService.checkCidr(input.serviceNetwork);
        input.name = input.name || 'network';
        input.labels = input.labels || [];
        const safe = copyNetwork(input);
        await configService.saveNetwork(safe);
        // TODO audit here
        return res.status(200).json(safe);

    }))

routerNetworkAuthenticated.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new network`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        const input = req.body as Network;
        input.id = Util.randomNumberString(16);

        await inputService.checkCidr(input.clientNetwork);
        await inputService.checkCidr(input.serviceNetwork);
        input.name = input.name || 'network';
        input.labels = input.labels || [];
        const safe = copyNetwork(input);
        await configService.saveNetwork(safe);
        //TODO audit
        return res.status(200).json(safe);

    }))







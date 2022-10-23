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
import { cloneGroup, Group } from "../model/group";




/////////////////////////////////  group //////////////////////////////////
export const routerGroupAuthenticated = express.Router();


/* routerGroupAuthenticated.get('/users',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`getting group users`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const allUsers = await configService.getUsersBy();
        const simpleUsers = allUsers.items.map(x => {
            return { id: x.id, username: x.username, groupIds: x.groupIds }
        })
        return res.status(200).json({
            items: simpleUsers
        });

    })) */



routerGroupAuthenticated.get('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting group with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const group = await configService.getGroup(id);
        if (!group) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no group');

        //const gateways = await configService.getGatewaysByGroupId(group.id);

        return res.status(200).json(group);

    }))

routerGroupAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        const ids = req.query.ids as string;
        logger.info(`getting groups`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        let items: Group[] = [];
        if (search) {
            const groups = await configService.getGroupsBySearch(search.toLowerCase());
            items = items.concat(groups);

        } else
            if (ids) {
                const parts = ids.split(',');
                for (const id of parts) {
                    const group = await configService.getGroup(id);
                    if (group)
                        items.push(group);
                }

            } else
                items = await configService.getGroupsAll();

        return res.status(200).json({ items: items });

    }))

routerGroupAuthenticated.delete('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`delete group with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const group = await configService.getGroup(id);
        if (!group) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no group');

        await configService.deleteGroup(group.id);
        //TODO audit
        return res.status(200).json({});

    }))





routerGroupAuthenticated.put('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as Group;
        logger.info(`changing group settings for ${input.id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        await inputService.checkNotEmpty(input.id);
        const group = await configService.getGroup(input.id);
        if (!group) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no group');

        await inputService.checkNotEmpty(input.name);
        input.name = input.name || 'group';
        input.labels = input.labels || [];
        const safe = cloneGroup(input);
        //copy original one
        safe.insertDate = group.insertDate;
        safe.updateDate = new Date().toISOString();
        await configService.saveGroup(safe);
        // TODO audit here
        return res.status(200).json(safe);

    }))

routerGroupAuthenticated.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new group`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        const input = req.body as Group;
        input.id = Util.randomNumberString(16);

        await inputService.checkNotEmpty(input.name);

        input.name = input.name || 'group';
        input.labels = input.labels || [];
        const safe = cloneGroup(input);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        await configService.saveGroup(safe);
        //TODO audit
        return res.status(200).json(safe);

    }))









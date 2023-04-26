import express from "express";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import passport from "passport";
import { ConfigService } from "../service/configService";
import { RBACDefault } from "../model/rbac";
import { authorizeAsAdmin } from "./commonApi";
import { cloneNetwork, Network } from "../model/network";
import { AuthSession } from "../model/authSession";
import { cloneIpIntelligenceList, cloneIpIntelligenceSource, IpIntelligenceList, IpIntelligenceSource } from "../model/IpIntelligence";
import IPCIDR from "ip-cidr";
import fsp from 'fs/promises'
import multer from 'multer';
import { once } from "events";
import { DevicePosture, cloneDevicePosture } from "../model/authenticationProfile";
const upload = multer({ dest: '/tmp/uploads/', limits: { fileSize: process.env.NODE == 'development' ? 2 * 1024 * 1024 * 1024 : 5 * 1024 * 1024 } });

/////////////////////////////////  device posture //////////////////////////////////
export const routerDeviceAuthenticated = express.Router();



//  /device/posture

routerDeviceAuthenticated.get('/posture/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting device posture with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const posture = await configService.getDevicePosture(id);
        if (!posture) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrGroupNotFound, 'no group');

        return res.status(200).json(posture);

    }))

routerDeviceAuthenticated.get('/posture',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        const ids = req.query.ids as string;
        logger.info(`getting device postures`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        let items: DevicePosture[] = [];
        if (search) {
            const postures = await configService.getDevicePosturesBySearch(search.toLowerCase());
            items = items.concat(postures);

        } else
            if (ids) {
                const parts = ids.split(',');
                for (const id of parts) {
                    const group = await configService.getDevicePosture(id);
                    if (group)
                        items.push(group);
                }

            } else
                items = await configService.getDevicePosturesAll();

        return res.status(200).json({ items: items });

    }))

routerDeviceAuthenticated.delete('/posture/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`delete device posture with id: ${id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;


        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const posture = await configService.getDevicePosture(id);
        if (!posture) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrGroupNotFound, 'no group');

        const { before } = await configService.deleteDevicePosture(posture.id);
        await auditService.logDeleteDevicePosture(currentSession, currentUser, before);

        return res.status(200).json({});

    }))





routerDeviceAuthenticated.put('/posture',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as DevicePosture;
        logger.info(`changing device posture for ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkNotEmpty(input.id);
        const posture = await configService.getDevicePosture(input.id);
        if (!posture) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrGroupNotFound, 'no group');

        await inputService.checkNotEmpty(input.name);
        input.name = input.name || 'device posture';
        input.labels = input.labels || [];
        const safe = cloneDevicePosture(input);
        //copy original one
        safe.insertDate = posture.insertDate;
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.saveDevicePosture(safe);
        await auditService.logSaveDevicePosture(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerDeviceAuthenticated.post('/posture',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new device posture`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const input = req.body as DevicePosture;
        input.id = Util.randomNumberString(16);

        await inputService.checkNotEmpty(input.name);

        input.name = input.name || 'device posture';
        input.labels = input.labels || [];
        const safe = cloneDevicePosture(input);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.saveGroup(safe);
        await auditService.logSaveGroup(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

















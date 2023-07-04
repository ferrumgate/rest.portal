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
import { authorizeAsAdmin, authorizeAsAdminOrReporter } from "./commonApi";
import { cloneNetwork, Network } from "../model/network";
import { AuthSession } from "../model/authSession";
import { cloneIpIntelligenceList, cloneIpIntelligenceSource, IpIntelligenceList, IpIntelligenceSource } from "../model/ipIntelligence";
import IPCIDR from "ip-cidr";
import fsp from 'fs/promises'
import multer from 'multer';
import { once } from "events";
import { DevicePosture, cloneDevicePosture } from "../model/authenticationProfile";
import { SearchDeviceLogsRequest } from "../service/esService";
const upload = multer({ dest: '/tmp/uploads/', limits: { fileSize: process.env.NODE == 'development' ? 2 * 1024 * 1024 * 1024 : 100 * 1024 * 1024 } });

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
        if (!posture) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrDevicePostureNotFound, 'no device posture');

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
                    const posture = await configService.getDevicePosture(id);
                    if (posture)
                        items.push(posture);
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
        if (!posture) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrDevicePostureNotFound, 'no device posture');

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
        if (!posture) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrDevicePostureNotFound, 'no device posture');

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

        const { before, after } = await configService.saveDevicePosture(safe);
        await auditService.logSaveDevicePosture(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))



/////////////////////////////////  /insights/device //////////////////////////////////
export const routerInsightsDeviceAuthenticated = express.Router();




routerInsightsDeviceAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdminOrReporter),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchDeviceLogsRequest;
        if (!Util.isUndefinedOrNull(query.isHealthy))
            query.isHealthy = (query.isHealthy as any) == 'true' ? true : false;
        logger.info(`getting device logs`);
        const appService = req.appService as AppService;
        const auditService = appService.auditService;
        const activityService = appService.activityService;
        const deviceService = appService.deviceService;


        const data = await deviceService.search(query);
        return res.status(200).json({ total: data.total, page: query.page, pageSize: query.pageSize, items: data.items });

    }))


















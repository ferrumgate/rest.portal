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
import { IpIntelligenceBWItem } from "../model/IpIntelligence";


/////////////////////////////////  ip intelligence //////////////////////////////////
export const routerIpIntelligenceAuthenticated = express.Router();



routerIpIntelligenceAuthenticated.get('/blacklist',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const ip = req.query.ip;
        const ids = req.query.ids as string;
        const page = req.query.page;
        const pageSize = req.query.pageSize;
        logger.info(`query ip intelligence blacklist`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        let items: IpIntelligenceBWItem[] = [];
        let total = 0;
        if (ip) {
            const data = await configService.getIpIntelligenceBlackListItemByIp(ip.toLowerCase());
            if (data)
                items.push(data);
            total = items.length;

        } else
            if (ids) {
                const parts = ids.split(',');
                for (const id of parts) {
                    const data = await configService.getIpIntelligenceBlackListItem(id);
                    if (data)
                        items.push(data);
                }
                total = items.length;

            } else {
                if (!pageSize) {
                    const data = await configService.getIpIntelligenceBlackList();
                    total = data.length;
                    items = items.concat(data);
                } else {
                    const data = await configService.getIpIntelligenceBlackListBy(page, pageSize);
                    total = data.total;
                    items = items.concat(data.items);
                }
            }

        return res.status(200).json({ total: total, items: items });

    }))

routerIpIntelligenceAuthenticated.delete('/blacklist/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete ip intelligence blacklist with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const item = await configService.getIpIntelligenceBlackListItem(id);
        if (!item) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNetworkNotFound, 'no network');

        const { before } = await configService.deleteIpIntelligenceBlackListItem(item.id);
        await auditService.logDeleteIpIntelligenceBlackList(currentSession, currentUser, before);
        return res.status(200).json({});

    }))


function cloneIpIntelligenceBWItem(data: any) {
    return { id: data.id, insertDate: data.insertDate, val: data.val };
}
routerIpIntelligenceAuthenticated.post('/blacklist',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new ip intelligence blacklist`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const input = req.body as IpIntelligenceBWItem;
        input.id = Util.randomNumberString(16);
        input.insertDate = new Date().toISOString();

        await inputService.checkCidr(input.val);
        const safe = cloneIpIntelligenceBWItem(input);
        const { before, after } = await configService.saveIpIntelligenceBlackListItem(safe);
        await auditService.logSaveIpIntelligenceBlackListItem(currentSession, currentUser, before, after);
        return res.status(200).json(safe);

    }))







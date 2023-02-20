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
import IPCIDR from "ip-cidr";


/////////////////////////////////  ip intelligence //////////////////////////////////
export const routerIpIntelligenceAuthenticated = express.Router();



routerIpIntelligenceAuthenticated.get('(\/blacklist|\/whitelist)',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const isBlackListRequest = req.path.includes('/blacklist');
        const ip = req.query.ip;
        const ids = req.query.ids as string;
        const page = req.query.page;
        const pageSize = req.query.pageSize;
        logger.info(`query ip intelligence ${isBlackListRequest ? 'blacklist' : 'whitelist'}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        let items: IpIntelligenceBWItem[] = [];
        let total = 0;
        if (ip) {
            const data =
                isBlackListRequest ?
                    await configService.getIpIntelligenceBlackListItemByIp(ip.toLowerCase()) :
                    await configService.getIpIntelligenceWhiteListItemByIp(ip.toLowerCase());
            if (data)
                items.push(data);
            total = items.length;

        } else
            if (ids) {
                const parts = ids.split(',');
                for (const id of parts) {
                    const data = isBlackListRequest ?
                        await configService.getIpIntelligenceBlackListItem(id) :
                        await configService.getIpIntelligenceWhiteListItem(id);
                    if (data)
                        items.push(data);
                }
                total = items.length;

            } else {
                if (!pageSize) {
                    const data = isBlackListRequest ?
                        await configService.getIpIntelligenceBlackList() :
                        await configService.getIpIntelligenceWhiteList();
                    total = data.length;
                    items = items.concat(data);
                } else {
                    const data = isBlackListRequest ?
                        await configService.getIpIntelligenceBlackListBy(page, pageSize) :
                        await configService.getIpIntelligenceWhiteListBy(page, pageSize);
                    total = data.total;
                    items = items.concat(data.items);
                }
            }

        return res.status(200).json({ total: total, items: items });

    }))

routerIpIntelligenceAuthenticated.delete('(\/blacklist|\/whitelist)/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const isBlackListRequest = req.path.includes('/blacklist');
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete ip intelligence ${isBlackListRequest ? 'blacklist' : 'whitelist'} with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const item = isBlackListRequest ?
            await configService.getIpIntelligenceBlackListItem(id) :
            await configService.getIpIntelligenceWhiteListItem(id);
        if (!item) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNetworkNotFound, 'no network');


        const { before } = isBlackListRequest ?
            await configService.deleteIpIntelligenceBlackListItem(item.id) :
            await configService.deleteIpIntelligenceWhiteListItem(item.id);
        isBlackListRequest ?
            await auditService.logDeleteIpIntelligenceBlackList(currentSession, currentUser, before) :
            await auditService.logDeleteIpIntelligenceWhiteList(currentSession, currentUser, before);
        return res.status(200).json({});

    }))


function cloneIpIntelligenceBWItem(data: IpIntelligenceBWItem): IpIntelligenceBWItem {
    return { id: data.id, insertDate: data.insertDate, val: data.val, description: data.description };
}
routerIpIntelligenceAuthenticated.post('(\/blacklist|\/whitelist)',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const isBlackListRequest = req.path.includes('/blacklist');
        logger.info(`saving a new ip intelligence ${isBlackListRequest ? 'blacklist' : 'whitelist'}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const inputs = req.body as { items: IpIntelligenceBWItem[] };
        let results: { item: IpIntelligenceBWItem, errMsg?: string }[] = [];
        let results2: IpIntelligenceBWItem[] = [];
        //first check all of input data , if they are valid
        for (const input of inputs.items) {
            try {
                input.id = Util.randomNumberString(16);
                input.insertDate = new Date().toISOString();

                await inputService.checkCidr(input.val);
                results2.push(input);
            } catch (err: any) {
                logger.error(err);
                results.push({ item: input, errMsg: err.message })
            }
        }

        //check if they exits
        for (const input of results2) {
            try {
                const cidr = new IPCIDR(input.val);
                input.val = Util.cidrNormalize(input.val);
                let exists = false;
                const existItem = isBlackListRequest ?
                    await configService.getIpIntelligenceBlackListItemByIp(cidr.addressStart.correctForm()) :
                    await configService.getIpIntelligenceWhiteListItemByIp(cidr.addressStart.correctForm());
                if (existItem) {
                    const existsItemCidr = new IPCIDR(existItem.val);
                    const isStartContains = existsItemCidr.contains(cidr.addressStart.correctForm());
                    const isEndContains = existsItemCidr.contains(cidr.addressEnd.correctForm());
                    if (isStartContains && isEndContains)
                        exists = true;

                }
                if (exists) {
                    results.push({ item: input, errMsg: 'already exists' });
                } else {
                    const safe = cloneIpIntelligenceBWItem(input);
                    const { before, after } = isBlackListRequest ?
                        await configService.saveIpIntelligenceBlackListItem(safe) :
                        await configService.saveIpIntelligenceWhiteListItem(safe);
                    isBlackListRequest ?
                        await auditService.logSaveIpIntelligenceBlackListItem(currentSession, currentUser, before, after) :
                        await auditService.logSaveIpIntelligenceWhiteListItem(currentSession, currentUser, before, after);
                    results.push({ item: input })
                }
            } catch (err: any) {
                logger.error(err);
                results.push({ item: input, errMsg: err.message })
            }
        }
        return res.status(200).json({ results: results });

    }))







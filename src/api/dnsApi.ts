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
import { cloneIpIntelligenceList, cloneIpIntelligenceSource, IpIntelligenceList, IpIntelligenceSource } from "../model/ipIntelligence";
import IPCIDR from "ip-cidr";
import fsp from 'fs/promises'
import multer from 'multer';
import { once } from "events";
import { DnsRecord, cloneDnsRecord } from "../model/dns";


/////////////////////////////////  dns //////////////////////////////////
export const routerDnsAuthenticated = express.Router();


// dns/records

routerDnsAuthenticated.get('/record',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        logger.info(`query dns records`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        let lists: DnsRecord[] = await configService.getDnsRecords();
        if (search) {
            lists = lists.filter(x => {
                if (x.fqdn.toLowerCase().includes(search)) return true;
                if (x.ip.includes(search)) return true;
                if (x.labels?.includes(search)) return true;
                return false;
            })
        }
        return res.status(200).json({ items: lists, });

    }))


routerDnsAuthenticated.delete('/record/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete dns record with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const item = await configService.getDnsRecord(id);
        if (!item) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no ip intellegence list');


        const { before } = await configService.deleteDnsRecord(item.id);
        await auditService.logDeleteDnsRecord(currentSession, currentUser, before);

        return res.status(200).json({});

    }))



routerDnsAuthenticated.put('/record',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as DnsRecord;
        logger.info(`changing dns record ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const ipIntelligenceService = appService.ipIntelligenceService;

        await inputService.checkNotEmpty(input.id);
        await inputService.checkNotEmpty(input.fqdn);
        await inputService.checkDomain(input.fqdn);
        await inputService.checkNotEmpty(input.ip);
        await inputService.checkIp(input.ip);

        const item = await configService.getDnsRecord(input.id);
        if (!item) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no dns record');

        const safe = cloneDnsRecord(input);
        safe.insertDate = item.insertDate;
        safe.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveDnsRecord(safe);
        await auditService.logSaveDnsRecord(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))


routerDnsAuthenticated.post('/record',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new dns record`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;


        const input = req.body as DnsRecord;
        input.id = Util.randomNumberString(16);

        await inputService.checkNotEmpty(input.fqdn);
        await inputService.checkDomain(input.fqdn);
        await inputService.checkIp(input.ip);


        const safe = cloneDnsRecord(input);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.saveDnsRecord(safe);
        await auditService.logSaveDnsRecord(currentSession, currentUser, before, after);
        return res.status(200).json(safe);

    }))
















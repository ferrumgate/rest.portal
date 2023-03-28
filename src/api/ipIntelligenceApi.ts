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
const upload = multer({ dest: '/tmp/uploads/', limits: { fileSize: process.env.NODE == 'development' ? 2 * 1024 * 1024 * 1024 : 5 * 1024 * 1024 } });

/////////////////////////////////  ip intelligence //////////////////////////////////
export const routerIpIntelligenceAuthenticated = express.Router();



//  /ip/intelligence/source
routerIpIntelligenceAuthenticated.get('/source',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`query ip intelligence source`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const sources = await configService.getIpIntelligenceSources();
        return res.status(200).json({ items: sources });

    }))

routerIpIntelligenceAuthenticated.delete('/source/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete ip intelligence source with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const source = await configService.getIpIntelligenceSource(id);
        if (!source) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no ip intellengence source');

        const { before } = await configService.deleteIpIntelligenceSource(source.id);
        await auditService.logDeleteIpIntelligenceSource(currentSession, currentUser, before);
        return res.status(200).json({});

    }))

routerIpIntelligenceAuthenticated.put('/source',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as IpIntelligenceSource;
        logger.info(`changing ip intelligence source for ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkNotEmpty(input.id);
        await inputService.checkNotEmpty(input.apiKey);
        const source = await configService.getIpIntelligenceSource(input.id);
        if (!source) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no ip intelligence source');


        input.name = input.type;
        const safe = cloneIpIntelligenceSource(input);
        safe.insertDate = source.insertDate;
        safe.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveIpIntelligenceSource(safe);
        await auditService.logSaveIpIntelligenceSource(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerIpIntelligenceAuthenticated.post('/source',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new ip intelligence source`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const input = req.body as IpIntelligenceSource;
        input.id = Util.randomNumberString(16);

        await inputService.checkNotEmpty(input.apiKey);

        input.name = input.type;

        const safe = cloneIpIntelligenceSource(input);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveIpIntelligenceSource(safe);
        await auditService.logSaveIpIntelligenceSource(currentSession, currentUser, before, after);
        return res.status(200).json(safe);

    }))


routerIpIntelligenceAuthenticated.post('/source/check',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as IpIntelligenceSource;
        logger.info(`check ip intelligence source ${input.type}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const ipIntelligence = appService.ipIntelligenceService;


        await inputService.checkNotEmpty(input.apiKey);
        await ipIntelligence.check(input);

        return res.status(200).json({});

    }))


// ip/intelligence/list


routerIpIntelligenceAuthenticated.post('/list/file',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(upload.single('file')),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`uploading a file`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const isSystemConfigured = await configService.getIsConfigured();
        if (!isSystemConfigured) {
            logger.warn(`system is not configured yet`);
            throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
        }
        const file = req.file;
        const key = Util.randomNumberString(16);
        /* let readStream: fs.ReadStream | null = null;
        let writeStream: fs.WriteStream | null = null;
        try {

            await fsp.mkdir('/tmp/files');
            const path = `/tmp/files/${key}`
            writeStream = fs.createWriteStream(path);
            readStream = fs.createReadStream(file.path)
            readStream.on('close', () => { writeStream?.close(); writeStream = null; readStream = null; });
            readStream.pipe(writeStream);
            await once(readStream, 'close');

        } finally {
            await fsp.unlink(file.path);
            writeStream?.close();

        } */

        await fsp.mkdir('/tmp/uploads', { recursive: true });
        const path = `/tmp/uploads/${key}`
        const buf = await fsp.readFile(file.path, { encoding: 'binary' });
        await fsp.writeFile(path, buf);

        return res.status(200).json({ key: key });

    }))





routerIpIntelligenceAuthenticated.get('/list/:id/file',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(upload.single('file')),
    asyncHandler(async (req: any, res: any, next: any) => {
        let id = req.params.id;

        logger.info(`downloading a file`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const ipIntelligence = appService.ipIntelligenceService;

        const isSystemConfigured = await configService.getIsConfigured();
        if (!isSystemConfigured) {
            logger.warn(`system is not configured yet`);
            throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
        }

        const list = await configService.getIpIntelligenceList(id);
        if (!list) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no ip intellegence list');

        res.attachment(`${list.name}_${new Date().toISOString()}`);
        await ipIntelligence.listService.getAllListItems(list, () => true, async (item: string) => {
            res.write(item);
            res.write('\n');
        })
        res.write('\n');
        return res.end();

    }))



routerIpIntelligenceAuthenticated.get('/list',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        logger.info(`query ip intelligence list`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const ipIntelligence = appService.ipIntelligenceService;
        const inputService = appService.inputService;
        let lists: IpIntelligenceList[] = [];
        if (search && inputService.checkIp(search, false)) {
            const listIds = await ipIntelligence.listService.getByIpAll(search);
            const allLists = await configService.getIpIntelligenceLists();
            allLists.filter(x => listIds.items.includes(x.id)).forEach(y => lists.push(y));


        } else {
            lists = await configService.getIpIntelligenceLists();
            if (search) {
                lists = lists.filter(x => {
                    if (x.name.toLowerCase().includes(search)) return true;
                    if (x.labels?.find(y => y.toLowerCase().includes(search))) return true;
                    if (x.http?.url.includes(search)) return true;
                    if (x.file?.source?.includes(search)) return true;
                    return false;
                })
            }
        }
        let statusList = await ipIntelligence.listService.getListStatusBulk(lists);
        return res.status(200).json({ items: lists, itemsStatus: statusList });

    }))


routerIpIntelligenceAuthenticated.delete('/list/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete ip intelligence list with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const ipIntelligence = appService.ipIntelligenceService;

        const list = await configService.getIpIntelligenceList(id);
        if (!list) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no ip intellegence list');

        await ipIntelligence.listService.deleteList(list);

        const { before } = await configService.deleteIpIntelligenceList(list.id);
        await auditService.logDeleteIpIntelligenceList(currentSession, currentUser, before);

        return res.status(200).json({});

    }))


routerIpIntelligenceAuthenticated.put('/list/:id/reset',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete ip intelligence list with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const ipIntelligence = appService.ipIntelligenceService;

        const list = await configService.getIpIntelligenceList(id);
        if (!list) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no ip intellegence list');

        await ipIntelligence.listService.resetList(list);
        await auditService.logResetIpIntelligenceList(currentSession, currentUser, list, list);

        list.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveIpIntelligenceList(list);
        await auditService.logSaveIpIntelligenceList(currentSession, currentUser, before, after);

        return res.status(200).json({});

    }))


routerIpIntelligenceAuthenticated.put('/list',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as IpIntelligenceList;
        logger.info(`changing ip intelligence list ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const ipIntelligenceService = appService.ipIntelligenceService;

        await inputService.checkNotEmpty(input.id);
        await inputService.checkNotEmpty(input.name);
        if (input.http) {
            await inputService.checkNotEmpty(input.http.url);
        }
        const list = await configService.getIpIntelligenceList(input.id);
        if (!list) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no ip intelligence source');

        //if item is file
        let fileUploadedName = input.file?.key;//we must set here, next fuction will delete this

        const safe = cloneIpIntelligenceList(input);
        safe.insertDate = list.insertDate;
        safe.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveIpIntelligenceList(safe);
        await auditService.logSaveIpIntelligenceList(currentSession, currentUser, before, after);
        if (fileUploadedName && after) {//log file to redis intelligence
            const path = `/tmp/uploads/${fileUploadedName}`
            await ipIntelligenceService.listService.saveListFile(after, path);
            await ipIntelligenceService.listService.deleteListStatus(after);
            await fsp.unlink(path);
        }

        return res.status(200).json(safe);

    }))


routerIpIntelligenceAuthenticated.post('/list',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(upload.single('file')),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new ip intelligence list`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const ipIntelligenceService = appService.ipIntelligenceService;

        const input = req.body as IpIntelligenceList;
        input.id = Util.randomNumberString(16);

        await inputService.checkNotEmpty(input.name);
        if (input.http) {
            await inputService.checkNotEmpty(input.http.url);
        }
        if (input.file) {
            await inputService.checkNotEmpty(input.file.source);
        }
        //if item is file
        let fileUploadedName = input.file?.key;//we must set here, next fuction will delete this

        const safe = cloneIpIntelligenceList(input);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();




        const { before, after } = await configService.saveIpIntelligenceList(safe);
        await auditService.logSaveIpIntelligenceList(currentSession, currentUser, before, after);
        if (fileUploadedName && after) {//log file to redis intelligence
            const path = `/tmp/uploads/${fileUploadedName}`
            await ipIntelligenceService.listService.saveListFile(after, path);
            await fsp.unlink(path);
        }
        return res.status(200).json(safe);

    }))
















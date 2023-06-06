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
import fsp from 'fs/promises'
import multer from 'multer';
import { once } from "events";
import { FqdnIntelligenceList, FqdnIntelligenceSource, cloneFqdnIntelligenceList, fqdnCategories } from "../model/fqdnIntelligence";
import { cloneFqdnIntelligenceSource } from "../model/fqdnIntelligence";
const upload = multer({ dest: '/tmp/uploads/', limits: { fileSize: process.env.NODE == 'development' ? 2 * 1024 * 1024 * 1024 : 5 * 1024 * 1024 } });

/////////////////////////////////  fqdn intelligence //////////////////////////////////
export const routerFqdnIntelligenceAuthenticated = express.Router();



//  /fqdn/intelligence/source
routerFqdnIntelligenceAuthenticated.get('/source',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`query fqdn intelligence source`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const sources = await configService.getFqdnIntelligenceSources();
        return res.status(200).json({ items: sources });

    }))

routerFqdnIntelligenceAuthenticated.delete('/source/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete fqdn intelligence source with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const source = await configService.getFqdnIntelligenceSource(id);
        if (!source) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrFqdnIntelligenceSourceNotFound, 'no fqdn intellengence source');

        const { before } = await configService.deleteFqdnIntelligenceSource(source.id);
        await auditService.logDeleteFqdnIntelligenceSource(currentSession, currentUser, before);
        return res.status(200).json({});

    }))

routerFqdnIntelligenceAuthenticated.put('/source',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as FqdnIntelligenceSource;
        logger.info(`changing fqdn intelligence source for ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkNotEmpty(input.id);
        await inputService.checkNotEmpty(input.apiKey);
        const source = await configService.getFqdnIntelligenceSource(input.id);
        if (!source) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrFqdnIntelligenceSourceNotFound, 'no fqdn intelligence source');


        input.name = input.type;
        const safe = cloneFqdnIntelligenceSource(input);
        safe.insertDate = source.insertDate;
        safe.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveFqdnIntelligenceSource(safe);
        await auditService.logSaveFqdnIntelligenceSource(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerFqdnIntelligenceAuthenticated.post('/source',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new fqdn intelligence source`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const input = req.body as FqdnIntelligenceSource;
        input.id = Util.randomNumberString(16);

        await inputService.checkNotEmpty(input.apiKey);

        input.name = input.type;

        const safe = cloneFqdnIntelligenceSource(input);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveFqdnIntelligenceSource(safe);
        await auditService.logSaveFqdnIntelligenceSource(currentSession, currentUser, before, after);
        return res.status(200).json(safe);

    }))


routerFqdnIntelligenceAuthenticated.post('/source/check',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as FqdnIntelligenceSource;
        logger.info(`check fqdn intelligence source ${input.type}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const fqdnIntelligence = appService.fqdnIntelligenceService;


        await inputService.checkNotEmpty(input.apiKey);
        await fqdnIntelligence.check(input);

        return res.status(200).json({});

    }))


// fqdn/intelligence/list


routerFqdnIntelligenceAuthenticated.post('/list/file',
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





routerFqdnIntelligenceAuthenticated.get('/list/:id/file',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(upload.single('file')),
    asyncHandler(async (req: any, res: any, next: any) => {
        let id = req.params.id;

        logger.info(`downloading fqdn file ${id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const fqdnIntelligence = appService.fqdnIntelligenceService;

        const isSystemConfigured = await configService.getIsConfigured();
        if (!isSystemConfigured) {
            logger.warn(`system is not configured yet`);
            throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
        }

        const list = await configService.getFqdnIntelligenceList(id);
        if (!list) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrFqdnIntelligenceSourceNotFound, 'no fqdn intellegence list');

        res.attachment(`${list.name}_${new Date().toISOString()}`);
        await fqdnIntelligence.listService.getAllListItems(list, () => true, async (item: string) => {
            res.write(item);
            res.write('\n');
        })
        res.write('\n');
        return res.end();

    }))



routerFqdnIntelligenceAuthenticated.get('/list',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        logger.info(`query fqdn intelligence list`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const fqdnIntelligence = appService.fqdnIntelligenceService;
        const inputService = appService.inputService;
        let lists: FqdnIntelligenceList[] = [];
        if (search && inputService.checkDomain(search, false)) {
            const listIds = await fqdnIntelligence.listService.getByFqdnAll(search);
            const allLists = await configService.getFqdnIntelligenceLists();
            allLists.filter(x => listIds.items.includes(x.id)).forEach(y => lists.push(y));



        }
        if (!lists.length) {
            lists = await configService.getFqdnIntelligenceLists();
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
        let statusList = await fqdnIntelligence.listService.getListStatusBulk(lists);
        return res.status(200).json({ items: lists, itemsStatus: statusList });

    }))


routerFqdnIntelligenceAuthenticated.delete('/list/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete fqdn intelligence list with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const fqdnIntelligence = appService.fqdnIntelligenceService;

        const list = await configService.getFqdnIntelligenceList(id);
        if (!list) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrFqdnIntelligenceSourceNotFound, 'no fqdn intellegence list');

        await fqdnIntelligence.listService.deleteList(list);

        const { before } = await configService.deleteFqdnIntelligenceList(list.id);
        await auditService.logDeleteFqdnIntelligenceList(currentSession, currentUser, before);

        return res.status(200).json({});

    }))


routerFqdnIntelligenceAuthenticated.put('/list/:id/reset',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete fqdn intelligence list with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const fqdnIntelligence = appService.fqdnIntelligenceService;

        const list = await configService.getFqdnIntelligenceList(id);
        if (!list) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrFqdnIntelligenceSourceNotFound, 'no fqdn intellegence list');

        await fqdnIntelligence.listService.resetList(list);
        await auditService.logResetFqdnIntelligenceList(currentSession, currentUser, list, list);

        list.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveFqdnIntelligenceList(list);
        await auditService.logSaveFqdnIntelligenceList(currentSession, currentUser, before, after);

        return res.status(200).json({});

    }))


routerFqdnIntelligenceAuthenticated.put('/list',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as FqdnIntelligenceList;
        logger.info(`changing fqdn intelligence list ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const fqdnIntelligenceService = appService.fqdnIntelligenceService;

        await inputService.checkNotEmpty(input.id);
        await inputService.checkNotEmpty(input.name);
        if (input.http) {
            await inputService.checkNotEmpty(input.http.url);
        }
        const list = await configService.getFqdnIntelligenceList(input.id);
        if (!list) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrFqdnIntelligenceSourceNotFound, 'no fqdn intelligence source');

        //if item is file
        let fileUploadedName = input.file?.key;//we must set here, next fuction will delete this

        const safe = cloneFqdnIntelligenceList(input);
        safe.insertDate = list.insertDate;
        safe.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveFqdnIntelligenceList(safe);
        await auditService.logSaveFqdnIntelligenceList(currentSession, currentUser, before, after);
        if (fileUploadedName && after) {//log file to redis intelligence
            const path = `/tmp/uploads/${fileUploadedName}`
            await fqdnIntelligenceService.listService.saveListFile(after, path);
            await fqdnIntelligenceService.listService.deleteListStatus(after);
            await fsp.unlink(path);
        } else if (after) {
            await fqdnIntelligenceService.listService.deleteListStatus(after);
        }

        return res.status(200).json(safe);

    }))


routerFqdnIntelligenceAuthenticated.post('/list',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(upload.single('file')),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new fqdn intelligence list`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const fqdnIntelligenceService = appService.fqdnIntelligenceService;

        const input = req.body as FqdnIntelligenceList;
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

        const safe = cloneFqdnIntelligenceList(input);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();




        const { before, after } = await configService.saveFqdnIntelligenceList(safe);
        await auditService.logSaveFqdnIntelligenceList(currentSession, currentUser, before, after);
        if (fileUploadedName && after) {//log file to redis intelligence
            const path = `/tmp/uploads/${fileUploadedName}`
            await fqdnIntelligenceService.listService.saveListFile(after, path);
            await fsp.unlink(path);
        }
        return res.status(200).json(safe);

    }))


// category list

//  /fqdn/intelligence/category
routerFqdnIntelligenceAuthenticated.get('/category',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`query fqdn intelligence category`);
        const appService = req.appService as AppService;
        return res.status(200).json({ items: fqdnCategories });

    }))















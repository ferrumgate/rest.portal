import express from "express";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AuthSession } from "../model/authSession";
import { NodeDetail, cloneNode } from "../model/network";
import { User } from "../model/user";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { AppService } from "../service/appService";
import { Util } from "../util";
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import { authorizeAsAdmin } from "./commonApi";
import { Node } from '../model/network'


/////////////////////////////////  node //////////////////////////////////
export const routerNodeAuthenticated = express.Router();

routerNodeAuthenticated.get('/alive',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`get alive nodes`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const nodeService = appService.nodeService;

        let items: NodeDetail[] = [];
        items = await nodeService.getAllAlive();
        return res.status(200).json({
            items: items
        });
    }))

/* routerNodeAuthenticated.post('/alive',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),//TODO change to token later
    asyncHandler(async (req: any, res: any, next: any) => {
        const node = req.body as NodeDetail;
        logger.info(`update alive node ${node.id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const nodeService = appService.nodeService;

        await nodeService.saveAlive(node);
        return res.status(200).json({
        });
    }))
 */
routerNodeAuthenticated.get('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting node with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const node = await configService.getNode(id);
        if (!node) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNodeNotFound, 'no node');

        return res.status(200).json(node);

    }))

function nodeDetailToNode(x: NodeDetail) {
    let node: Node = {
        id: x.id,
        name: x.hostname || 'unknown',
        insertDate: new Date().toISOString(),
        labels: [], updateDate: new Date().toISOString()
    }
    return node;
}


routerNodeAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        const ids = req.query.ids as string;
        logger.info(`query node`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const nodeService = appService.nodeService;

        let items: Node[] = [];

        if (search) {
            const nodes = await configService.getNodesBy(search.toLowerCase());
            items = items.concat(nodes);

        } else {
            //find alive items and add them as real         
            items = await configService.getNodesAll();
        }

        return res.status(200).json({
            items: items
        });
    }))




routerNodeAuthenticated.delete('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`delete node with id: ${id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const nodeService = appService.nodeService;

        const node = await configService.getNode(id);
        const nodeAlive = await nodeService.getAliveById(id);
        if (!node && !nodeAlive) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNodeNotFound, 'no node');

        await nodeService.deleteAliveById(id);
        if (node) {
            const { before } = await configService.deleteNode(node.id);
            await auditService.logDeleteNode(currentSession, currentUser, before);
        }

        return res.status(200).json({});

    }))



routerNodeAuthenticated.put('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as Node;
        logger.info(`changing node settings for ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const nodeService = appService.nodeService;
        const auditService = appService.auditService;


        await inputService.checkNotEmpty(input.id);
        const node = await configService.getNode(input.id);
        if (!node) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNodeNotFound, 'no node');

        input.name = input.name || 'node';
        input.labels = input.labels || [];
        const safe = cloneNode(input);

        const { before, after } = await configService.saveNode(safe);
        await auditService.logSaveNode(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerNodeAuthenticated.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new node`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const nodeService = appService.nodeService;

        const input = req.body as Node;
        input.id = Util.randomNumberString(16);

        input.name = input.name || 'node';
        input.labels = input.labels || [];
        const safe = cloneNode(input)

        const { before, after } = await configService.saveNode(safe);
        await auditService.logSaveNode(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))







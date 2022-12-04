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
import { cloneNetwork, Network } from "../model/network";
import { AuthSession } from "../model/authSession";
import { SearchActivityLogsRequest, SearchSummaryRequest } from "../service/esService";


/////////////////////////////////  summary //////////////////////////////////
export const routerSummaryAuthenticated = express.Router();

routerSummaryAuthenticated.get('/config',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchActivityLogsRequest;
        logger.info(`getting summary config`);
        const appService = req.appService as AppService;
        const summaryService = appService.summaryService



        const data = await summaryService.getSummaryConfig();
        return res.status(200).json(data);

    }))

routerSummaryAuthenticated.get('/active',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchActivityLogsRequest;
        logger.info(`getting summary config`);
        const appService = req.appService as AppService;
        const summaryService = appService.summaryService



        const data = await summaryService.getSummaryActive();
        return res.status(200).json(data);

    }))

routerSummaryAuthenticated.get('/logintry',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchSummaryRequest;
        logger.info(`getting login try`);
        const appService = req.appService as AppService;
        const summaryService = appService.summaryService;
        const data = await summaryService.getSummaryLoginTry(query);
        return res.status(200).json(data);

    }))


routerSummaryAuthenticated.get('/createtunnel',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchSummaryRequest;
        logger.info(`getting create tunnel`);
        const appService = req.appService as AppService;
        const summaryService = appService.summaryService;
        const data = await summaryService.getSummaryCreateTunnel(query);
        return res.status(200).json(data);

    }))

routerSummaryAuthenticated.get('/2facheck',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchSummaryRequest;
        logger.info(`getting 2fa check`);
        const appService = req.appService as AppService;
        const summaryService = appService.summaryService;
        const data = await summaryService.getSummary2faCheck(query);
        return res.status(200).json(data);

    }))

routerSummaryAuthenticated.get('/userloginsuccess',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchSummaryRequest;
        logger.info(`getting 2fa check`);
        const appService = req.appService as AppService;
        const summaryService = appService.summaryService;
        const data = await summaryService.getSummaryUserLoginSuccess(query);
        return res.status(200).json(data);

    }))



routerSummaryAuthenticated.get('/userloginfailed',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchSummaryRequest;
        logger.info(`getting 2fa check`);
        const appService = req.appService as AppService;
        const summaryService = appService.summaryService;
        const data = await summaryService.getSummaryUserLoginFailed(query);
        return res.status(200).json(data);

    }))










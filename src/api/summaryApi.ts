import express from "express";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { User } from "../model/user";
import { AppService } from "../service/appService";
import { SearchActivityLogsRequest, SearchSummaryRequest, SearchSummaryUserRequest } from "../service/esService";
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import { authorizeAsAdminOrReporter } from "./commonApi";


/////////////////////////////////  summary //////////////////////////////////
export const routerSummaryAuthenticated = express.Router();

routerSummaryAuthenticated.get('/config',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdminOrReporter),
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
    asyncHandler(authorizeAsAdminOrReporter),
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
    asyncHandler(authorizeAsAdminOrReporter),
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
    asyncHandler(authorizeAsAdminOrReporter),
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
    asyncHandler(authorizeAsAdminOrReporter),
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
    asyncHandler(authorizeAsAdminOrReporter),
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
    asyncHandler(authorizeAsAdminOrReporter),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchSummaryRequest;
        logger.info(`getting 2fa check`);
        const appService = req.appService as AppService;
        const summaryService = appService.summaryService;
        const data = await summaryService.getSummaryUserLoginFailed(query);
        return res.status(200).json(data);

    }))

/**
 * @summary current user login try
 */
routerSummaryAuthenticated.get('/user/logintry',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchSummaryUserRequest;

        logger.info(`getting user login try`);
        const appService = req.appService as AppService;
        const summaryService = appService.summaryService;
        const inputService = appService.inputService;

        const currentUser = req.currentUser as User;
        query.username = currentUser.username;
        //important
        await inputService.checkNotEmpty(query.username);
        const data = await summaryService.getSummaryUserLoginTry(query);
        return res.status(200).json(data);

    }))

/**
* @summary current user login try hours
*/
routerSummaryAuthenticated.get('/user/logintryhours',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchSummaryUserRequest;

        logger.info(`getting user login try`);
        const appService = req.appService as AppService;
        const summaryService = appService.summaryService;
        const inputService = appService.inputService;

        const currentUser = req.currentUser as User;
        query.username = currentUser.username;
        //important
        await inputService.checkNotEmpty(query.username);
        const data = await summaryService.getSummaryUserLoginTryHours(query);
        return res.status(200).json(data);

    }))










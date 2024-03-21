import express from "express";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { Countries } from "../model/country";
import { AppService } from "../service/appService";
import { Util } from "../util";
import { passportAuthenticate, passportInit } from "./auth/passportInit";


/////////////////////////////////  data //////////////////////////////////
export const routerDataAuthenticated = express.Router();





routerDataAuthenticated.get('/country',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting country list`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        return res.status(200).json({ items: Countries });

    }))

routerDataAuthenticated.get('/timezone',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting timezone list`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const items = Util.timeZoneList();

        return res.status(200).json({ items: items });

    }))

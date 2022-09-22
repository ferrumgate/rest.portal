import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportInit } from "./auth/passportInit";
import passport from "passport";



/////////////////////////////////  public //////////////////////////////////
export const routerConfig = express.Router();
///   /config/public
routerConfig.get('/', asyncHandler(async (req: any, res: any, next: any) => {

    logger.info(`getting public config`);
    const appService = req.appService as AppService;
    const configService = appService.configService;

    const captcha = await configService.getCaptcha();
    const isConfigured = await configService.getIsConfigured();
    const authSettings = await configService.getAuthSettings();

    return res.status(200).json({
        captchaSiteKey: captcha.client,


    });

}))


////////////////////////////  login ////////////////////////////////////

routerConfig.get('/',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting login config`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const isConfigured = await configService.getIsConfigured();
        const authSettings = await configService.getAuthSettings();

        return res.status(200).json({
            isConfigured: isConfigured,
            isLocal: authSettings.isLocal ? 1 : 0,
            isGoogle: authSettings.google ? 1 : 0,
            isLinkedIn: authSettings.linkedin ? 1 : 0

        });

    }))

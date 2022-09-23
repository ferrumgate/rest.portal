import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportInit } from "./auth/passportInit";
import passport from "passport";
import { ConfigService } from "../service/configService";



/////////////////////////////////  public //////////////////////////////////
export const routerConfig = express.Router();
///   /config/public

/*
 * 
 * @param configService 
 * @returns public config data without authentication
 * @remark dont put sensitive data in this function
 */
async function getPublicConfig(configService: ConfigService) {
    const captcha = await configService.getCaptcha();
    const isConfigured = await configService.getIsConfigured();
    const authSettings = await configService.getAuthSettings();


    return {
        captchaSiteKey: captcha.client,
        isConfigured: isConfigured,
        login: {
            local: {
                isForgotPassword: authSettings.local.isForgotPassword,
                isRegister: authSettings.local.isRegister
            },
            google: authSettings.google ? {} : undefined,
            linkedin: authSettings.linkedin ? {} : undefined
        }
    };
}

routerConfig.get('/', asyncHandler(async (req: any, res: any, next: any) => {

    logger.info(`getting public config`);
    const appService = req.appService as AppService;
    const configService = appService.configService;

    const publicConfig = await getPublicConfig(configService);
    return res.status(200).json(publicConfig);

}))


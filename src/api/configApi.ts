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
import { authorizeAsAdmin } from "./commonApi";
import { RedisService } from "../service/redisService";
import { Captcha } from "../model/captcha";




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


/////////////////////////////////  authenticated router //////////////////////////////////
export const routerConfigAuthenticated = express.Router();

////////////////////////////// common ///////////////////////////////////////

routerConfigAuthenticated.get('/common',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {



        logger.info(`getting common config parameters`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const url = await configService.getUrl();
        const domain = await configService.getDomain();

        return res.status(200).json({ url: url, domain: domain });

    }))
const configChangedChannel = '/config/changed'
routerConfigAuthenticated.put('/common',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as { url?: string, domain?: string };
        logger.info(`changing config common settings`);

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const url = await configService.getUrl();
        const domain = await configService.getDomain();
        if (input.url && input.url != url) {
            await inputService.checkUrl(input.url);
            await configService.setUrl(input.url);
            //inform system that config changed
            await redisService.publish(configChangedChannel, `url=${input.url}`)
            //TODO audit

        }

        if (input.domain && input.domain != domain) {
            await inputService.checkDomain(input.domain);
            await configService.setDomain(input.domain);
            //inform system that config changed
            await redisService.publish(configChangedChannel, `domain=${input.domain}`)
            //TODO audit
        }
        const urlAfter = await configService.getUrl();
        const domainAfter = await configService.getDomain();
        return res.status(200).json({ url: urlAfter, domain: domainAfter });

    }))




////////////////////////////// captcha ///////////////////////////////////////

routerConfigAuthenticated.get('/captcha',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting config captcha parameters`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const captcha = await configService.getCaptcha();


        return res.status(200).json(captcha);

    }))

routerConfigAuthenticated.put('/captcha',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as Captcha
        logger.info(`changing config captcha settings`);

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const captcha = await configService.getCaptcha();
        if (captcha.client != input.client || captcha.server != input.server) {
            await configService.setCaptcha(input);
            //TODO audit
        }
        const again = await configService.getCaptcha();
        return res.status(200).json(again);

    }))



///////////////// 

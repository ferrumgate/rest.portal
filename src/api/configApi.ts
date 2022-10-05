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
import * as diff from 'deep-object-diff';
import { EmailSettings } from "../model/emailSettings";
import { AuthCommon, AuthLocal, BaseLocal, BaseOAuth } from "../model/authSettings";
import { util } from "chai";
import { config } from "process";




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
            google: authSettings.oauth?.providers.find(x => x.type == 'google') ? {} : undefined,
            linkedin: authSettings.oauth?.providers.find(x => x.type == 'linkedin') ? {} : undefined
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


////////////////////////////// email ///////////////////////////////////////

routerConfigAuthenticated.get('/email',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting config email parameters`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const email = await configService.getEmailSettings();

        return res.status(200).json(email);

    }))


function getEmailSettingFrom(input: EmailSettings): EmailSettings {
    if (input.type == 'empty')
        return {
            type: 'empty', user: '', fromname: '', pass: ''
        }
    if (input.type == 'google') return {
        type: 'google',
        user: input.user,
        fromname: input.user,
        pass: input.pass,
    }
    if (input.type == 'office365') return {
        type: 'office365',
        user: input.user,
        fromname: input.user,
        pass: input.pass,
    }
    if (input.type == 'smtp') return {
        type: 'smtp',
        user: input.user,
        pass: input.pass,
        fromname: input.fromname,
        host: input.host,
        port: input.port,
        isSecure: input.isSecure

    }
    throw new RestfullException(400, ErrorCodes.ErrBadArgument, "no way to convert email settings")
}
routerConfigAuthenticated.put('/email',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as EmailSettings
        logger.info(`changing config email settings`);

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        await inputService.checkIfExists(input);
        const emailService = appService.emailService;
        const email = await configService.getEmailSettings();
        const diffFields = diff.detailedDiff(email, input);
        if (Object.keys(diffFields)) {
            const setting = getEmailSettingFrom(input);
            await configService.setEmailSettings(setting);
            await emailService.reset();
            //TODO audit
        }
        const again = await configService.getEmailSettings();
        return res.status(200).json(again);

    }));

routerConfigAuthenticated.delete('/email',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {


        logger.info(`deleting config email settings`);

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const emailService = appService.emailService;
        const email = await configService.getEmailSettings();

        if (email) {
            await configService.setEmailSettings({ type: 'empty', fromname: '', pass: '', user: '' });
            await emailService.reset();
            //TODO audit
        }
        const again = await configService.getEmailSettings();
        return res.status(200).json(again);

    }));

routerConfigAuthenticated.post('/email/check',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as EmailSettings

        logger.info(`checking email settings`);

        const appService = req.appService as AppService;
        const emailService = appService.emailService;
        const inputService = appService.inputService;
        const user = req.currentUser as User;
        const email = user.username;

        let isError = false;
        let errorMessage = '';

        try {
            await inputService.checkIfExists(input, 'input is null');
            await inputService.checkEmail(email);

            await emailService.sendWith({
                subject: 'test email ' + new Date().toISOString(),
                to: email,
                text: 'test email works'
            }, input, true);

        } catch (err: any) {

            isError = true;
            if (err instanceof RestfullException) {
                errorMessage = err.code;

            }
            else {

                const stack = err.stack as string;
                errorMessage = stack?.split('\n').map(x => x.trim()).find(x => x.includes('Invalid login') || x.includes('ECONNREFUSED')) || err.code;


            }

        }

        return res.status(200).json({ isError: isError, errorMessage: errorMessage });

    }));



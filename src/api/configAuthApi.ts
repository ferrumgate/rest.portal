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





/////////////////////////////////  authenticated router //////////////////////////////////
export const routerConfigAuthAuthenticated = express.Router();

/////////////////////////////////// auth settings ////////////////////////////

routerConfigAuthAuthenticated.get('/common',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`getting config auth common`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const auth = await configService.getAuthSettings()

        return res.status(200).json(auth.common || {});

    }))
function copyAuthCommon(common: AuthCommon): AuthCommon {
    return {

    }
}
routerConfigAuthAuthenticated.put('/common',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as AuthCommon;
        logger.info(`getting config auth common`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        await inputService.checkIfExists(input);
        //make it safe input data
        const safe = copyAuthCommon(input);
        await configService.setAuthSettingsCommon(safe);
        const output = await configService.getAuthSettingsCommon();
        //TODO audit
        return res.status(200).json(output);

    }))

/////////////////////////////   /auth/local
routerConfigAuthAuthenticated.get('/local',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`getting config auth local`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const local = await configService.getAuthSettingsLocal();

        return res.status(200).json(local);

    }))

function copyAuthLocal(input: AuthLocal): AuthLocal {
    return {
        id: input.id, baseType: input.baseType, name: input.name,
        type: input.type, isForgotPassword: input.isForgotPassword,
        isRegister: input.isRegister, tags: input.tags

    }
}
routerConfigAuthAuthenticated.put('/local',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as BaseLocal;
        logger.info(`getting config auth local`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        await inputService.checkIfExists(input);
        const safe = copyAuthLocal(input)
        await configService.setAuthSettingsLocal(safe);
        //TODO audit
        const local = await configService.getAuthSettingsLocal();
        return res.status(200).json(local);

    }))

function copyAuthOAuth(auth: BaseOAuth): BaseOAuth {
    if (auth.baseType == 'oauth' && (auth.type == 'google' || auth.type == 'linkedin'))
        return {
            id: auth.id,
            baseType: auth.baseType,
            clientId: auth.clientId,
            clientSecret: auth.clientSecret,
            name: auth.name,
            type: auth.type,
            tags: auth.tags
        }
    throw new Error('not implemented copyAuthOAuth');
}
/////////////////////
routerConfigAuthAuthenticated.get('/oauth/providers',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const ids = req.query.ids as string;
        logger.info(`getting config auth oauth providers`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const oauth = await configService.getAuthSettingOAuth();
        let providers = oauth?.providers || [];
        if (ids) {
            let idList = ids.split(',');
            providers = providers.filter(x => idList.includes(x.id));
        }
        return res.status(200).json({ items: providers });

    }))

routerConfigAuthAuthenticated.post('/oauth/providers',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const provider = req.body as BaseOAuth;
        logger.info(`getting config oauth providers`);

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        await inputService.checkIfExists(provider);
        await inputService.checkIfNotExits(provider.id);
        await inputService.checkIfExists(provider.name);
        await inputService.checkIfExists(provider.type);
        await inputService.checkIfExists(provider.baseType);

        const oauth = await configService.getAuthSettingOAuth();
        const indexA = oauth?.providers.findIndex(x => x.type == provider.type && x.baseType == provider.baseType);

        if (Number(indexA) >= 0) {
            throw new RestfullException(400, ErrorCodes.ErrAllreadyExits, "input data is prolem");
        }
        provider.id = Util.randomNumberString();
        const safe = copyAuthOAuth(provider);
        await configService.addAuthSettingOAuth(safe);
        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.put('/oauth/providers',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`update config oauth provider`);
        const input = req.body as BaseOAuth;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        await inputService.checkIfExists(input);
        await inputService.checkIfExists(input.id);
        const item = (await configService.getAuthSettingOAuth()).providers.find(x => x.id);
        await inputService.checkIfExists(item);
        if (item?.type != input.type && item?.baseType != input.baseType)
            throw new RestfullException(400, ErrorCodes.ErrDataVerifyFailed, 'item type or basetype not valid');
        const safe = copyAuthOAuth(input);
        await configService.addAuthSettingOAuth(safe)
        //TODO audit
        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.delete('/oauth/providers/:id',
    asyncHandler(passportInit),
    passport.authenticate(['jwt', 'headerapikey'], { session: false, }),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`delete config oauth provider`);
        const { id } = req.params;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const item = await (await configService.getAuthSettingOAuth()).providers.find(x => x.id == id);
        if (item)
            await configService.deleteAuthSettingOAuth(id);
        //TODO audit
        return res.status(200).json({});

    }))






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
import { authorizeAsAdmin } from "./commonApi";
import { RedisService } from "../service/redisService";
import { Captcha } from "../model/captcha";
import * as diff from 'deep-object-diff';
import { EmailSettings } from "../model/emailSettings";
import { AuthCommon, AuthLocal, BaseLdap, BaseLocal, BaseOAuth } from "../model/authSettings";
import { util } from "chai";
import { config } from "process";





/////////////////////////////////  authenticated router //////////////////////////////////
export const routerConfigAuthAuthenticated = express.Router();

/////////////////////////////////// auth settings ////////////////////////////

routerConfigAuthAuthenticated.get('/common',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
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
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
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
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`getting config auth local`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const local = await configService.getAuthSettingsLocal();

        return res.status(200).json(local);

    }))

function copyAuthLocal(auth: AuthLocal): AuthLocal {
    return {
        id: auth.id, baseType: auth.baseType, name: auth.name,
        type: auth.type, isForgotPassword: auth.isForgotPassword,
        isRegister: auth.isRegister, tags: auth.tags,
        isEnabled: auth.isEnabled,
        securityProfile: {
            ips: auth.securityProfile?.ips,
            clocks: auth.securityProfile?.clocks,
            locations: auth.securityProfile?.locations
        }

    }
}
routerConfigAuthAuthenticated.put('/local',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
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














///////////////////// oauth2 /////////////////////////////////////////
function copyAuthOAuth(auth: BaseOAuth): BaseOAuth {
    if (auth.baseType == 'oauth' && (auth.type == 'google' || auth.type == 'linkedin'))
        return {
            id: auth.id,
            baseType: auth.baseType,
            clientId: auth.clientId,
            clientSecret: auth.clientSecret,
            name: auth.name,
            type: auth.type,
            tags: auth.tags,
            isEnabled: auth.isEnabled,
            securityProfile: {
                ips: auth.securityProfile?.ips,
                clocks: auth.securityProfile?.clocks,
                locations: auth.securityProfile?.locations
            }
        }
    throw new Error('not implemented copyAuthOAuth');
}

routerConfigAuthAuthenticated.get('/oauth/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
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
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const provider = req.body as BaseOAuth;
        logger.info(`getting config auth oauth providers`);

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        // check input data
        await inputService.checkIfExists(provider);
        await inputService.checkIfNotExits(provider.id);
        await inputService.checkIfExists(provider.name);
        await inputService.checkIfExists(provider.type);
        await inputService.checkIfExists(provider.baseType);

        const oauth = await configService.getAuthSettingOAuth();
        const indexA = oauth?.providers.findIndex(x => x.type == provider.type && x.baseType == provider.baseType);

        if (Number(indexA) >= 0) {
            throw new RestfullException(400, ErrorCodes.ErrAllreadyExits, "input data is problem");
        }
        provider.id = Util.randomNumberString();
        const safe = copyAuthOAuth(provider);
        await configService.addAuthSettingOAuth(safe);
        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.put('/oauth/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`update config auth oauth provider`);
        const input = req.body as BaseOAuth;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        //check input data
        await inputService.checkIfExists(input);
        await inputService.checkIfExists(input.id);

        const item = (await configService.getAuthSettingOAuth()).providers.find(x => x.id == input.id);
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
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`delete config auth oauth provider`);
        const { id } = req.params;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const item = (await configService.getAuthSettingOAuth()).providers.find(x => x.id == id);
        if (item)
            await configService.deleteAuthSettingOAuth(id);
        //TODO audit
        return res.status(200).json({});

    }))








///////////////////// ldap /////////////////////////////////////////
function copyAuthLdap(auth: BaseLdap): BaseLdap {
    if (auth.baseType == 'ldap' && auth.type == 'activedirectory')
        return {
            id: auth.id,
            baseType: auth.baseType,
            name: auth.name,
            type: auth.type,
            tags: auth.tags,
            host: auth.host,
            bindDN: auth.bindDN,
            bindPass: auth.bindPass,
            searchBase: auth.searchBase,
            searchFilter: auth.searchFilter,
            usernameField: auth.usernameField,
            groupnameField: auth.groupnameField,
            allowedGroups: auth.allowedGroups,
            isEnabled: auth.isEnabled,
            securityProfile: {
                ips: auth.securityProfile?.ips,
                clocks: auth.securityProfile?.clocks,
                locations: auth.securityProfile?.locations
            }
        }
    throw new Error('not implemented copyAuthLdap');
}

routerConfigAuthAuthenticated.get('/ldap/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const ids = req.query.ids as string;
        logger.info(`getting config auth ldap providers`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const ldap = await configService.getAuthSettingLdap();
        let providers = ldap?.providers || [];
        if (ids) {
            let idList = ids.split(',');
            providers = providers.filter(x => idList.includes(x.id));
        }
        return res.status(200).json({ items: providers });

    }))

routerConfigAuthAuthenticated.post('/ldap/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const provider = req.body as BaseLdap;
        logger.info(`getting config auth ldap providers`);

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        //check input data 
        await inputService.checkIfExists(provider);
        await inputService.checkIfNotExits(provider.id);
        await inputService.checkIfExists(provider.name);
        await inputService.checkIfExists(provider.type);
        await inputService.checkIfExists(provider.baseType);
        await inputService.checkIfExists(provider.host);
        await inputService.checkIfExists(provider.bindDN);
        await inputService.checkIfExists(provider.bindPass);
        await inputService.checkIfExists(provider.searchBase);
        await inputService.checkIfExists(provider.usernameField);
        await inputService.checkIfExists(provider.groupnameField);

        // check if same provider exists
        const ldap = await configService.getAuthSettingLdap();
        const indexA = ldap?.providers.findIndex(x => x.type == provider.type && x.baseType == provider.baseType);

        if (Number(indexA) >= 0) {
            throw new RestfullException(400, ErrorCodes.ErrAllreadyExits, "input data is problem");
        }
        provider.id = Util.randomNumberString();
        const safe = copyAuthLdap(provider);
        await configService.addAuthSettingLdap(safe);
        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.put('/ldap/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`update config auth ldap provider`);
        const input = req.body as BaseLdap;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        //check input
        await inputService.checkIfExists(input);
        await inputService.checkIfExists(input.id);
        await inputService.checkIfExists(input.host);
        await inputService.checkIfExists(input.bindDN);
        await inputService.checkIfExists(input.bindPass);
        await inputService.checkIfExists(input.searchBase);
        await inputService.checkIfExists(input.usernameField);
        await inputService.checkIfExists(input.groupnameField);
        const item = (await configService.getAuthSettingLdap()).providers.find(x => x.id == input.id);
        await inputService.checkIfExists(item);
        if (item?.type != input.type && item?.baseType != input.baseType)
            throw new RestfullException(400, ErrorCodes.ErrDataVerifyFailed, 'item type or basetype not valid');
        const safe = copyAuthLdap(input);
        await configService.addAuthSettingLdap(safe)
        //TODO audit
        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.delete('/ldap/providers/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`delete config auth ldap provider`);
        const { id } = req.params;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const item = (await configService.getAuthSettingLdap()).providers.find(x => x.id == id);
        if (item)
            await configService.deleteAuthSettingLdap(id);
        //TODO audit
        return res.status(200).json({});

    }))







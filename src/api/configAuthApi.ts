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
import { EmailSetting } from "../model/emailSetting";
import { AuthCommon, AuthLocal, BaseLdap, BaseLocal, BaseOAuth, BaseOpenId, BaseRadius, BaseSaml } from "../model/authSettings";
import { util } from "chai";
import { config } from "process";
import { AuthSession } from "../model/authSession";





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

        const common = await configService.getAuthSettingCommon()

        return res.status(200).json(common || {});

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
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkIfExists(input);
        //make it safe input data
        const safe = copyAuthCommon(input);
        const { before, after } = await configService.setAuthSettingCommon(safe);
        await auditService.logsetAuthSettingCommon(currentSession, currentUser, before, after);

        const output = await configService.getAuthSettingCommon();
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

        const local = await configService.getAuthSettingLocal();

        return res.status(200).json(local);

    }))

function copyAuthLocal(auth: AuthLocal): AuthLocal {
    return {
        baseType: auth.baseType, name: auth.name,
        type: auth.type, isForgotPassword: auth.isForgotPassword,
        isRegister: auth.isRegister, tags: auth.tags,
        isEnabled: auth.isEnabled,
        updateDate: auth.updateDate,
        insertDate: auth.insertDate,


    }
}
routerConfigAuthAuthenticated.put('/local',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as BaseLocal;
        logger.info(`getting config auth local`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkIfExists(input);
        const db = await configService.getAuthSettingLocal();
        const safe = copyAuthLocal(input);
        safe.insertDate = db.insertDate;
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.setAuthSettingLocal(safe);
        await auditService.logsetAuthSettingLocal(currentSession, currentUser, before, after);

        const local = await configService.getAuthSettingLocal();
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
            insertDate: auth.insertDate,
            updateDate: auth.updateDate,
            saveNewUser: auth.saveNewUser

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
        const indexA = oauth?.providers?.findIndex(x => x.type == provider.type && x.baseType == provider.baseType);

        if (Number(indexA) >= 0) {
            throw new RestfullException(400, ErrorCodes.ErrAllreadyExits, ErrorCodes.ErrAllreadyExits, "input data is problem");
        }
        provider.id = Util.randomNumberString(16);
        const safe = copyAuthOAuth(provider);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        await configService.addAuthSettingOAuth(safe);
        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.put('/oauth/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`update config auth oauth provider`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const input = req.body as BaseOAuth;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        //check input data
        await inputService.checkIfExists(input);
        await inputService.checkIfExists(input.id);

        const item = (await configService.getAuthSettingOAuth()).providers.find(x => x.id == input.id);
        await inputService.checkIfExists(item);
        if (item?.type != input.type && item?.baseType != input.baseType)
            throw new RestfullException(400, ErrorCodes.ErrDataVerifyFailed, ErrorCodes.ErrDataVerifyFailed, 'item type or basetype not valid');
        const safe = copyAuthOAuth(input);
        safe.insertDate = item.insertDate;
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.addAuthSettingOAuth(safe)
        await auditService.logaddAuthSettingOAuth(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.delete('/oauth/providers/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`delete config auth oauth provider`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const { id } = req.params;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const item = (await configService.getAuthSettingOAuth()).providers.find(x => x.id == id);
        if (item) {
            const { before } = await configService.deleteAuthSettingOAuth(id);
            await auditService.logdeleteAuthSettingOAuth(currentSession, currentUser, before);
        }

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
            insertDate: auth.insertDate,
            updateDate: auth.updateDate,
            saveNewUser: auth.saveNewUser

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
        logger.info(`saving config auth ldap providers`);

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
        const indexA = ldap?.providers?.findIndex(x => x.type == provider.type && x.baseType == provider.baseType);

        if (Number(indexA) >= 0) {
            throw new RestfullException(400, ErrorCodes.ErrAllreadyExits, ErrorCodes.ErrAllreadyExits, "input data is problem");
        }
        provider.id = Util.randomNumberString(16);
        const safe = copyAuthLdap(provider);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        await configService.addAuthSettingLdap(safe);
        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.put('/ldap/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`update config auth ldap provider`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const input = req.body as BaseLdap;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

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
            throw new RestfullException(400, ErrorCodes.ErrDataVerifyFailed, ErrorCodes.ErrDataVerifyFailed, 'item type or basetype not valid');
        const safe = copyAuthLdap(input);
        safe.insertDate = item.insertDate;
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.addAuthSettingLdap(safe)
        await auditService.logaddAuthSettingLdap(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.delete('/ldap/providers/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`delete config auth ldap provider`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const { id } = req.params;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const item = (await configService.getAuthSettingLdap()).providers.find(x => x.id == id);
        if (item) {
            const { before } = await configService.deleteAuthSettingLdap(id);
            await auditService.logDeleteAuthSettingLdap(currentSession, currentUser, before);
        }

        return res.status(200).json({});

    }))









///////////////////// saml /////////////////////////////////////////
function copyAuthSaml(auth: BaseSaml): BaseSaml {
    if (auth.baseType == 'saml')
        return {
            id: auth.id,
            baseType: auth.baseType,
            name: auth.name,
            type: auth.type,
            tags: auth.tags,
            isEnabled: auth.isEnabled,

            cert: auth.cert,
            issuer: auth.issuer,
            loginUrl: auth.loginUrl,
            nameField: auth.nameField,
            usernameField: auth.usernameField,
            fingerPrint: auth.fingerPrint,
            insertDate: auth.insertDate,// no problem about copy these client unsafe variables we will override in api calls
            updateDate: auth.updateDate, // no problem about copy these client unsafe variables, we will override in api calls
            saveNewUser: auth.saveNewUser

        }
    throw new Error('not implemented copyAuthLdap');
}



routerConfigAuthAuthenticated.get('/saml/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const ids = req.query.ids as string;
        logger.info(`getting config auth saml providers`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const saml = await configService.getAuthSettingSaml();
        let providers = saml?.providers || [];
        if (ids) {
            let idList = ids.split(',');
            providers = providers.filter(x => idList.includes(x.id));
        }
        return res.status(200).json({ items: providers });

    }))

routerConfigAuthAuthenticated.post('/saml/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const provider = req.body as BaseSaml;
        logger.info(`saving config auth saml providers`);

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        //check input data 
        await inputService.checkIfExists(provider);
        await inputService.checkIfNotExits(provider.id);
        await inputService.checkIfExists(provider.name);
        await inputService.checkIfExists(provider.type);
        await inputService.checkIfExists(provider.baseType);
        await inputService.checkIfExists(provider.cert);
        await inputService.checkIfExists(provider.loginUrl);
        await inputService.checkIfExists(provider.issuer);
        await inputService.checkIfExists(provider.nameField);
        await inputService.checkIfExists(provider.usernameField);


        // check if same provider exists
        const saml = await configService.getAuthSettingSaml();
        const indexA = saml?.providers?.findIndex(x => x.type == provider.type && x.baseType == provider.baseType);

        if (Number(indexA) >= 0) {
            throw new RestfullException(400, ErrorCodes.ErrAllreadyExits, ErrorCodes.ErrAllreadyExits, "input data is problem");
        }
        provider.id = Util.randomNumberString(16);
        const safe = copyAuthSaml(provider);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        await configService.addAuthSettingSaml(safe);
        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.put('/saml/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`update config auth saml provider`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const input = req.body as BaseSaml;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        //check input
        await inputService.checkIfExists(input);
        await inputService.checkIfExists(input.id);
        await inputService.checkIfExists(input.loginUrl);
        await inputService.checkIfExists(input.issuer);
        await inputService.checkIfExists(input.cert);
        await inputService.checkIfExists(input.nameField);
        await inputService.checkIfExists(input.usernameField);

        const item = (await configService.getAuthSettingSaml()).providers.find(x => x.id == input.id);
        await inputService.checkIfExists(item);
        if (item?.type != input.type && item?.baseType != input.baseType)
            throw new RestfullException(400, ErrorCodes.ErrDataVerifyFailed, ErrorCodes.ErrDataVerifyFailed, 'item type or basetype not valid');
        const safe = copyAuthSaml(input);
        safe.insertDate = item.insertDate;
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.addAuthSettingSaml(safe)
        await auditService.logAddAuthSettingSaml(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.delete('/saml/providers/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`delete config auth saml provider`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const { id } = req.params;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const item = (await configService.getAuthSettingSaml()).providers.find(x => x.id == id);
        if (item) {
            const { before } = await configService.deleteAuthSettingSaml(id);
            await auditService.logDeleteAuthSettingSaml(currentSession, currentUser, before);
        }

        return res.status(200).json({});

    }))


////////////// open id

function copyAuthOpenId(auth: BaseOpenId): BaseOpenId {
    if (auth.baseType == 'openId')
        return {
            id: auth.id,
            baseType: auth.baseType,
            name: auth.name,
            type: auth.type,
            tags: auth.tags,
            isEnabled: auth.isEnabled,
            authName: auth.authName,



            discoveryUrl: auth.discoveryUrl,
            clientId: auth.clientId,
            clientSecret: auth.clientSecret,
            icon: auth.icon,
            insertDate: auth.insertDate,// no problem about copy these client unsafe variables we will override in api calls
            updateDate: auth.updateDate, // no problem about copy these client unsafe variables, we will override in api calls
            saveNewUser: auth.saveNewUser,

        }
    throw new Error('not implemented copyAuthLdap');
}

routerConfigAuthAuthenticated.get('/openid/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const ids = req.query.ids as string;
        logger.info(`getting config auth openid providers`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const openid = await configService.getAuthSettingOpenId();
        let providers = openid?.providers || [];
        if (ids) {
            let idList = ids.split(',');
            providers = providers.filter(x => idList.includes(x.id));
        }
        return res.status(200).json({ items: providers });

    }))

routerConfigAuthAuthenticated.post('/openid/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const provider = req.body as BaseOpenId;
        logger.info(`saving config auth openid providers`);

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        //check input data 
        await inputService.checkIfExists(provider);
        await inputService.checkIfNotExits(provider.id);
        await inputService.checkIfExists(provider.name);
        await inputService.checkIfExists(provider.type);
        await inputService.checkIfExists(provider.baseType);
        await inputService.checkIfExists(provider.authName);
        await inputService.checkIfExists(provider.discoveryUrl);
        await inputService.checkIfExists(provider.clientId);
        await inputService.checkIfExists(provider.clientSecret);


        // check if same provider exists
        const openid = await configService.getAuthSettingOpenId();
        const indexA = openid?.providers?.findIndex(x => x.type == provider.type && x.baseType == provider.baseType && x.authName == provider.authName);

        if (Number(indexA) >= 0) {
            throw new RestfullException(400, ErrorCodes.ErrAllreadyExits, ErrorCodes.ErrAllreadyExits, "input data is problem");
        }
        provider.id = Util.randomNumberString(16);
        const safe = copyAuthOpenId(provider);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        await configService.addAuthSettingOpenId(safe);
        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.put('/openid/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`update config auth openid provider`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const input = req.body as BaseOpenId;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        //check input
        await inputService.checkIfExists(input);
        await inputService.checkIfExists(input.id);
        await inputService.checkIfExists(input.name);
        await inputService.checkIfExists(input.authName);
        await inputService.checkIfExists(input.discoveryUrl);
        await inputService.checkIfExists(input.clientId);
        await inputService.checkIfExists(input.clientSecret);

        const item = (await configService.getAuthSettingOpenId()).providers.find(x => x.id == input.id);
        await inputService.checkIfExists(item);
        if (item?.type != input.type && item?.baseType != input.baseType)
            throw new RestfullException(400, ErrorCodes.ErrDataVerifyFailed, ErrorCodes.ErrDataVerifyFailed, 'item type or basetype not valid');
        const safe = copyAuthOpenId(input);
        safe.insertDate = item.insertDate;
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.addAuthSettingOpenId(safe)
        await auditService.logAddAuthSettingOpenId(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.delete('/openid/providers/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`delete config auth openid provider`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const { id } = req.params;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const item = (await configService.getAuthSettingOpenId()).providers.find(x => x.id == id);
        if (item) {
            const { before } = await configService.deleteAuthSettingOpenId(id);
            await auditService.logDeleteAuthSettingOpenId(currentSession, currentUser, before);
        }

        return res.status(200).json({});

    }))



////////////// radius

function copyAuthRadius(auth: BaseRadius): BaseRadius {
    if (auth.baseType == 'radius')
        return {
            id: auth.id,
            baseType: auth.baseType,
            name: auth.name,
            type: auth.type,
            tags: auth.tags,
            isEnabled: auth.isEnabled,
            authName: auth.authName,

            secret: auth.secret,
            host: auth.host,
            icon: auth.icon,
            insertDate: auth.insertDate,// no problem about copy these client unsafe variables we will override in api calls
            updateDate: auth.updateDate, // no problem about copy these client unsafe variables, we will override in api calls
            saveNewUser: auth.saveNewUser,

        }
    throw new Error('not implemented copyAuthRadius');
}

routerConfigAuthAuthenticated.get('/radius/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const ids = req.query.ids as string;
        logger.info(`getting config auth radius providers`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const radius = await configService.getAuthSettingRadius();
        let providers = radius?.providers || [];
        if (ids) {
            let idList = ids.split(',');
            providers = providers.filter(x => idList.includes(x.id));
        }
        return res.status(200).json({ items: providers });

    }))

routerConfigAuthAuthenticated.post('/radius/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const provider = req.body as BaseRadius;
        logger.info(`saving config auth radius providers`);

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


        // check if same provider exists
        const radius = await configService.getAuthSettingRadius();
        const indexA = radius?.providers?.findIndex(x => x.type == provider.type && x.baseType == provider.baseType);

        if (Number(indexA) >= 0) {
            throw new RestfullException(400, ErrorCodes.ErrAllreadyExits, ErrorCodes.ErrAllreadyExits, "input data is problem");
        }
        provider.id = Util.randomNumberString(16);
        const safe = copyAuthRadius(provider);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        await configService.addAuthSettingRadius(safe);
        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.put('/radius/providers',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`update config auth radius provider`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const input = req.body as BaseRadius;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        //check input
        await inputService.checkIfExists(input);
        await inputService.checkIfExists(input.id);
        await inputService.checkIfExists(input.name);
        await inputService.checkIfExists(input.type);
        await inputService.checkIfExists(input.baseType);
        await inputService.checkIfExists(input.host);


        const item = (await configService.getAuthSettingRadius()).providers.find(x => x.id == input.id);
        await inputService.checkIfExists(item);
        if (item?.type != input.type && item?.baseType != input.baseType)
            throw new RestfullException(400, ErrorCodes.ErrDataVerifyFailed, ErrorCodes.ErrDataVerifyFailed, 'item type or basetype not valid');
        const safe = copyAuthRadius(input);
        safe.insertDate = item.insertDate;
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.addAuthSettingRadius(safe)
        await auditService.logAddAuthSettingRadius(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerConfigAuthAuthenticated.delete('/radius/providers/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`delete config auth radius provider`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const { id } = req.params;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const item = (await configService.getAuthSettingRadius()).providers.find(x => x.id == id);
        if (item) {
            const { before } = await configService.deleteAuthSettingRadius(id);
            await auditService.logDeleteAuthSettingRadius(currentSession, currentUser, before);
        }

        return res.status(200).json({});

    }))


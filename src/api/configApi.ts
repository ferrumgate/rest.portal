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
import { AuthCommon, AuthLocal, BaseLocal, BaseOAuth } from "../model/authSettings";
import { util } from "chai";
import { config } from "process";
import { AuthSession } from "../model/authSession";
import { ESSetting } from "../model/esSetting";
import { ESService } from "../service/esService";
import { RedisConfigWatchService } from "../service/redisConfigWatchService";
import yaml from 'yaml';
import fsp from 'fs/promises';
import multer from 'multer';
import { Config } from "log4js";
import { attachActivitySession, attachActivityUser, saveActivity } from "./auth/commonAuth";
import { BrandSetting } from "../model/brandSetting";
const upload = multer({ dest: '/tmp/uploads/', limits: { fileSize: process.env.NODE == 'development' ? 2 * 1024 * 1024 * 1024 : 100 * 1024 * 1024 } });


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
    const oauth = await configService.getAuthSettingOAuth();
    const saml = await configService.getAuthSettingSaml();
    const ldap = await configService.getAuthSettingLdap();
    const local = await configService.getAuthSettingLocal();
    const openId = await configService.getAuthSettingOpenId();
    const brand = await configService.getBrand();

    const googleOAuth = oauth?.providers.find(x => x.type == 'google');
    const linkedOAuth = oauth?.providers.find(x => x.type == 'linkedin');
    const auth0 = saml?.providers.find(x => x.type == 'auth0');
    const azure = saml?.providers.find(x => x.type == 'azure');
    const openIds = openId.providers.filter(x => x.isEnabled);
    return {
        captchaSiteKey: captcha.client,
        isConfigured: isConfigured,
        login: {
            local: {
                isForgotPassword: local.isForgotPassword,
                isRegister: local.isRegister
            },
            oAuthGoogle: googleOAuth?.isEnabled ? {} : undefined,
            oAuthLinkedin: linkedOAuth?.isEnabled ? {} : undefined,
            samlAuth0: auth0?.isEnabled ? {} : undefined,
            samlAzure: azure?.isEnabled ? {} : undefined,
            //dont sent objects directly
            openId: openIds.map(x => {
                return { name: x.name, authName: x.authName, icon: x.icon }
            }),
            oauth: oauth.providers.filter(x => x.type == 'generic').map(x => {
                return { name: x.name, authName: x.authName, icon: x.icon }
            }),
            saml: saml.providers.filter(x => x.type == 'generic').map(x => {
                return { name: x.name, authName: x.authName, icon: x.icon }
            }),
        },
        brand: {
            ...brand
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
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {



        logger.info(`getting common config parameters`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const url = await configService.getUrl();
        const domain = await configService.getDomain();
        const httptoHttpsRedirect = await configService.getHttpToHttpsRedirect();

        return res.status(200).json({ url: url, domain: domain, httpsRedirect: httptoHttpsRedirect });

    }))

routerConfigAuthenticated.put('/common',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as { url?: string, domain?: string, httpsRedirect?: boolean };
        logger.info(`changing config common settings`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const url = await configService.getUrl();
        const domain = await configService.getDomain();
        const httpsRedirect = await configService.getHttpToHttpsRedirect();
        if (input.url && input.url != url) {
            await inputService.checkUrl(input.url);
            const { before, after } = await configService.setUrl(input.url);
            await auditService.logSetUrl(currentSession, currentUser, before, after);


        }

        if (input.domain && input.domain != domain) {
            await inputService.checkDomain(input.domain);
            const { before, after } = await configService.setDomain(input.domain);
            await auditService.logSetDomain(currentSession, currentUser, before, after);
        }
        if (input.httpsRedirect != httpsRedirect) {
            const { before, after } = await configService.setHttpToHttpsRedirect(input.httpsRedirect ? true : false);
            await auditService.logSetHttpToHttpsRedirect(currentSession, currentUser, before, after);
        }
        const urlAfter = await configService.getUrl();
        const domainAfter = await configService.getDomain();
        return res.status(200).json({ url: urlAfter, domain: domainAfter });

    }))




////////////////////////////// captcha ///////////////////////////////////////

routerConfigAuthenticated.get('/captcha',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
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
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as Captcha
        logger.info(`changing config captcha settings`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const captcha = await configService.getCaptcha();
        if (captcha.client != input.client || captcha.server != input.server) {
            const { before, after } = await configService.setCaptcha({
                client: input.client,
                server: input.server
            });
            await auditService.logSetCaptcha(currentSession, currentUser, before, after);
        }
        const again = await configService.getCaptcha();
        return res.status(200).json(again);

    }))


////////////////////////////// email ///////////////////////////////////////

routerConfigAuthenticated.get('/email',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting config email parameters`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const email = await configService.getEmailSetting();

        return res.status(200).json(email);

    }))


function getEmailSettingFrom(input: EmailSetting): EmailSetting {
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
    throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "no way to convert email settings")
}
routerConfigAuthenticated.put('/email',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as EmailSetting
        logger.info(`changing config email settings`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkIfExists(input);
        const emailService = appService.emailService;
        const email = await configService.getEmailSetting();
        const diffFields = diff.detailedDiff(email, input);
        if (Object.keys(diffFields)) {
            const setting = getEmailSettingFrom(input);
            const { before, after } = await configService.setEmailSetting(setting);
            await auditService.logSetEmailSetting(currentSession, currentUser, before, after);
            await emailService.reset();

        }
        const again = await configService.getEmailSetting();
        return res.status(200).json(again);

    }));

routerConfigAuthenticated.delete('/email',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {


        logger.info(`deleting config email settings`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const emailService = appService.emailService;
        const auditService = appService.auditService;

        const email = await configService.getEmailSetting();

        if (email) {
            const { before, after } = await configService.setEmailSetting({ type: 'empty', fromname: '', pass: '', user: '' });
            await auditService.logSetEmailSetting(currentSession, currentUser, before, after);
            await emailService.reset();

        }
        const again = await configService.getEmailSetting();
        return res.status(200).json(again);

    }));

routerConfigAuthenticated.post('/email/check',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as EmailSetting

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



////////////////////////////// es ///////////////////////////////////////

routerConfigAuthenticated.get('/es',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting config es parameters`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const es = await configService.getES();


        return res.status(200).json(es || {});

    }))

routerConfigAuthenticated.put('/es',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as ESSetting
        logger.info(`changing config es settings`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const es = await configService.getES();
        if (es.host != input.host || es.pass != input.pass || es.user || input.user || es.deleteOldRecordsMaxDays != input.deleteOldRecordsMaxDays) {
            const { before, after } = await configService.setES({
                host: input.host,
                deleteOldRecordsMaxDays: input.deleteOldRecordsMaxDays,
                pass: input.pass,
                user: input.user,

            });
            await auditService.logSetES(currentSession, currentUser, before, after);
        }
        const again = await configService.getES();
        return res.status(200).json(again);

    }))


routerConfigAuthenticated.post('/es/check',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as ESSetting
        logger.info(`checking config es settings`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        let errMsg = '';
        try {
            const es = new ESService(configService, input.host, input.user, input.pass);
            const indexes = await es.getAllIndexes();
        } catch (err: any) {
            logger.error(err);
            errMsg = err.message;
        }
        return res.status(200).json({ error: errMsg });

    }))

/////////  import / export config ///////////////////////////

routerConfigAuthenticated.get('/export/key',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`exporting config`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const random = Util.randomNumberString(32);
        await redisService.set(`/export/file/${random}`, random, { ttl: 10000 });
        return res.status(200).json({ key: random });

    }))

routerConfigAuthenticated.get('/export/:key',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { key } = req.params;
        logger.info(`exporting config`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const isSystemConfigured = await configService.getIsConfigured();
        if (!isSystemConfigured) {
            logger.warn(`system is not configured yet`);
            throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
        }


        const encKey = await redisService.get(`/export/file/${key}`, false) as string;
        if (!encKey) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodes.ErrNotFound, 'key is wrong');

        let conf = configService.createConfig();
        await configService.getConfig(conf);


        const str = yaml.stringify(conf);

        const encrypted = Util.encrypt(encKey, str);
        const randomFilename = Util.randomNumberString(8);
        const folder = `/tmp/uploads/${Util.randomNumberString()}`;
        await fsp.mkdir(folder, { recursive: true });
        const filepath = `${folder}/${randomFilename}`;
        await fsp.writeFile(filepath, encrypted);
        await redisService.delete(`/export/file/${encKey}`);
        await auditService.logConfigExport(currentSession, currentUser);
        return res.download(filepath, `${randomFilename}.txt`)
        //return res.status(200).json({ key: encrypted });

    }))



routerConfigAuthenticated.post('/import/:key',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(upload.single('config')),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { key } = req.params;
        logger.info(`importing config`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const isSystemConfigured = await configService.getIsConfigured();
        if (!isSystemConfigured) {
            logger.warn(`system is not configured yet`);
            throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
        }

        const file = req.file;
        const str = (await fsp.readFile(file.path)).toString();
        const decrpted = Util.decrypt(key, str);

        const conf = yaml.parse(decrpted) as Config;
        await configService.setConfig(conf);
        await fsp.unlink(file.path);

        await auditService.logConfigImport(currentSession, currentUser);
        return res.status(200).json({});

    }))




////////////////////////////// brand ///////////////////////////////////////

routerConfigAuthenticated.get('/brand',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting config brand parameters`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const brand = await configService.getBrand();


        return res.status(200).json(brand || {});

    }))

routerConfigAuthenticated.put('/brand',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const input = req.body as BrandSetting;
        logger.info(`changing config brand settings`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const redisService = appService.redisService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const brand = await configService.getBrand();
        if (brand.name != input.name || brand.logoBlack != input.logoBlack || brand.logoWhite != input.logoWhite) {
            if (input.logoBlack)
                if (!input.logoBlack.startsWith('data:image'))
                    throw new RestfullException(500, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "only image files");

            if (input.logoWhite)
                if (!input.logoWhite.startsWith('data:image'))
                    throw new RestfullException(500, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "only image files");
            const { before, after } = await configService.setBrand({ name: input.name, logoBlack: input.logoBlack, logoWhite: input.logoWhite });
            await auditService.logSetBrand(currentSession, currentUser, before, after);
        }
        const again = await configService.getBrand();
        return res.status(200).json(again);

    }))















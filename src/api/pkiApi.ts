import express from "express";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import passport from "passport";
import { ConfigService } from "../service/configService";
import { RBACDefault } from "../model/rbac";
import { authorizeAsAdmin } from "./commonApi";
import { cloneNetwork, Network } from "../model/network";
import { AuthSession } from "../model/authSession";
import { cloneIpIntelligenceList, cloneIpIntelligenceSource, IpIntelligenceList, IpIntelligenceSource } from "../model/IpIntelligence";
import IPCIDR from "ip-cidr";
import fsp from 'fs/promises'
import multer from 'multer';
import { once } from "events";
import { SSLCertificate, cloneSSlCertificate, cloneSSlCertificateEx } from "../model/cert";
import { SSLCertificateEx } from "../model/cert";
import { UtilPKI } from "../utilPKI";


/////////////////////////////////  pki //////////////////////////////////
export const routerPKIAuthenticated = express.Router();



//  /pki/intermediate
routerPKIAuthenticated.get('/intermediate',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`query pki intermediate`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const certs = await configService.getInSSLCertificateAllSensitive();
        return res.status(200).json({ items: certs });

    }))


routerPKIAuthenticated.post('/intermediate/:id/export',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const password = req.body.password;
        logger.info(`p12 download intermediate`);

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        await inputService.checkNotEmpty(password);
        const cert = await configService.getInSSLCertificateSensitive(id);
        if (!cert) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNotFound, 'no pki cert');
        if (cert.isSystem) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrSystemParameter, 'system parameter');
        const ca = await configService.getCASSLCertificate();
        const buffer = await UtilPKI.createP12_2(cert.privateKey || '', cert.publicCrt || '', ca.publicCrt || '', password);
        const folder = `/tmp/pki/${Util.randomNumberString()}`;
        await fsp.mkdir(folder, { recursive: true });
        const filepath = `${folder}/${Util.randomNumberString()}.p12`;
        await fsp.writeFile(filepath, buffer);
        return res.download(filepath, `${cert.name}.p12`)

    }))

routerPKIAuthenticated.delete('/intermediate/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete pki intermediate with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const cert = await configService.getInSSLCertificate(id);
        if (!cert) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no pki cert');
        if (cert.isSystem)
            throw new RestfullException(400, ErrorCodes.ErrSystemParameter, ErrorCodesInternal.ErrSystemParameter, 'you cannot delete system cert');

        const { before } = await configService.deleteInSSLCertificate(cert.id);
        await auditService.logDeleteCert(currentSession, currentUser, before);
        return res.status(200).json({});

    }))

routerPKIAuthenticated.put('/intermediate',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as SSLCertificateEx;
        logger.info(`changing pki intermediate with id: ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkNotEmpty(input.id);
        await inputService.checkNotEmpty(input.name);
        const cert = await configService.getInSSLCertificate(input.id);
        if (!cert) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no ip intelligence source');
        if (cert.isSystem)
            throw new RestfullException(400, ErrorCodes.ErrSystemParameter, ErrorCodesInternal.ErrSystemParameter, 'you cannot update system cert');

        cert.name = input.name;
        cert.updateDate = new Date().toISOString();
        cert.isEnabled = input.isEnabled ? true : false;
        const { before, after } = await configService.saveInSSLCertificate(cert);
        await auditService.logSaveCert(currentSession, currentUser, before, after);

        //always get again, thismakes system more secure, this is a safe function
        const ret = await configService.getInSSLCertificate(input.id);
        return res.status(200).json(ret);

    }))

routerPKIAuthenticated.post('/intermediate',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving pki intermediate`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const input = req.body as SSLCertificateEx;
        input.id = Util.randomNumberString(16);

        await inputService.checkNotEmpty(input.name);
        await inputService.checkNotEmpty(input.category);

        const safe = cloneSSlCertificateEx(input);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        safe.isSystem = false;
        safe.isEnabled = true;
        const ca = await configService.getCASSLCertificateSensitive();
        if (!ca) {
            throw new RestfullException(417, ErrorCodes.ErrSystemIsNotReady, ErrorCodesInternal.ErrSystemIsNotReady, 'no ca');
        }
        safe.parentId = ca.idEx;
        const { publicCrt, privateKey } = await UtilPKI.createCertSigned(input.name, 'ferrumgate', 10950, [], ca.publicCrt || '', ca.privateKey);
        safe.publicCrt = publicCrt;
        safe.privateKey = privateKey;

        const { before, after } = await configService.saveInSSLCertificate(safe);
        await auditService.logSaveCert(currentSession, currentUser, before, after);
        //allways get again, this make system more secure
        const ret = await configService.getInSSLCertificate(safe.id)
        return res.status(200).json(ret);

    }))


//  /pki/intermediate
routerPKIAuthenticated.get('/cert/web',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`query pki web`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const cert = await configService.getWebSSLCertificate();
        return res.status(200).json({ items: [cert] });

    }))


routerPKIAuthenticated.delete('/cert/web',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete pki web`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const cert = await configService.getWebSSLCertificateSensitive();
        if (!cert) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no pki cert');
        const safe = cloneSSlCertificate(cert);
        safe.idEx = cert.idEx;
        safe.name = 'Web';
        safe.labels = [];
        safe.isEnabled = true;
        safe.isSystem = false;
        safe.category = 'web';
        //delete  makes reset certificate and generates a new one
        const webIntermediate = (await configService.getInSSLCertificateAllSensitive()).filter(x => x.category == 'tls').find(x => x.labels.includes("for web"));
        if (!webIntermediate) {
            throw new RestfullException(417, ErrorCodes.ErrSystemIsNotReady, ErrorCodesInternal.ErrSystemIsNotReady, 'no web intermediate cert');
        }
        safe.parentId = webIntermediate.id;
        const url = await configService.getUrl();
        const domain1 = new URL(url).hostname;


        const { publicCrt, privateKey } = await UtilPKI.createCertSigned("Web", 'ferrumgate', 10950,
            [
                { type: 'domain', value: domain1 },

            ],
            webIntermediate.publicCrt || '', webIntermediate.privateKey);
        safe.publicCrt = publicCrt;
        safe.privateKey = privateKey;
        safe.updateDate = new Date().toISOString();
        const { before, after } = await configService.setWebSSLCertificate(safe);
        await auditService.logSaveCert(currentSession, currentUser, before, after);
        let ret = await configService.getWebSSLCertificate();
        return res.status(200).json(ret);

    }))

routerPKIAuthenticated.put('/cert/web',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as SSLCertificate;
        logger.info(`changing pki web`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;


        await inputService.checkNotEmpty(input.name);

        const cert = await configService.getWebSSLCertificate();
        if (!cert) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no ip intelligence source');

        const safe = cloneSSlCertificate(input);
        safe.idEx = cert.idEx;
        safe.name = input.name;
        safe.updateDate = new Date().toISOString();
        safe.isEnabled = input.isEnabled ? true : false;
        if (input.privateKey)
            safe.privateKey = input.privateKey;
        if (safe.publicCrt != input.publicCrt)
            safe.parentId = '';
        if (input.publicCrt)
            safe.publicCrt = input.publicCrt;
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.setWebSSLCertificate(safe);
        await auditService.logSaveCert(currentSession, currentUser, before, after);

        //always get again, thismakes system more secure, this is a safe function
        const ret = await configService.getWebSSLCertificate();
        return res.status(200).json(ret);

    }))


















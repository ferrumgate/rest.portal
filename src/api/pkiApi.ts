import express from "express";
import fsp from 'fs/promises';
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AuthSession } from "../model/authSession";
import { SSLCertificate, SSLCertificateEx, cloneSSlCertificate, cloneSSlCertificateEx } from "../model/cert";
import { cloneLetsEncrypt } from "../model/letsEncrypt";
import { User } from "../model/user";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { AppService } from "../service/appService";
import { AuditService } from "../service/auditService";
import { ConfigService } from "../service/configService";
import { Util } from "../util";
import { UtilPKI } from "../utilPKI";
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import { authorizeAsAdmin } from "./commonApi";



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
routerPKIAuthenticated.get('/ca',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`query pki ca `);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const certs = await configService.getCASSLCertificate();
        return res.status(200).json({ items: [certs] });

    }))


routerPKIAuthenticated.post('/intermediate/:id/export',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const password = req.body.password;
        const addChain = req.body.addChain;
        logger.info(`p12 download intermediate`);

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        await inputService.checkNotEmpty(password);
        const cert = await configService.getInSSLCertificateSensitive(id);
        if (!cert) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNotFound, 'no pki cert');
        if (cert.isSystem) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrSystemParameter, 'system parameter');
        const ca = await configService.getCASSLCertificate();
        let buffer: Uint8Array;
        if (addChain) {
            buffer = await UtilPKI.createP12_2(cert.privateKey || '', cert.publicCrt || '', ca.publicCrt || '', password);
        } else {
            buffer = await UtilPKI.createP12(cert.privateKey || '', cert.publicCrt || '', password,);
        }
        const folder = `/tmp/pki/${Util.randomNumberString()}`;
        await fsp.mkdir(folder, { recursive: true });
        const filepath = `${folder}/${Util.randomNumberString()}.p12`;
        await fsp.writeFile(filepath, buffer);
        await auditService.logExportCert(currentSession, currentUser, cert);
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

        const safe = cloneSSlCertificateEx(input);
        safe.updateDate = new Date().toISOString();
        safe.isSystem = false;
        cert.isEnabled = input.isEnabled ? true : false;

        const { before, after } = await configService.saveInSSLCertificate(safe);
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
        const { publicCrt, privateKey } = await UtilPKI.createCertSigned(input.name, 'ferrumgate', 9125, true, [], ca.publicCrt || '', ca.privateKey);
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


export async function resetWebCertificateOnly(configService: ConfigService,) {

    //delete  makes reset certificate and generates a new one
    const webIntermediate = (await configService.getInSSLCertificateAllSensitive()).filter(x => x.category == 'tls').find(x => x.usages.includes("for web"));
    if (!webIntermediate) {
        throw new RestfullException(417, ErrorCodes.ErrSystemIsNotReady, ErrorCodesInternal.ErrSystemIsNotReady, 'no web intermediate cert');
    }

    const url = await configService.getUrl();
    const domain1 = new URL(url).hostname;


    const { publicCrt, privateKey } = await UtilPKI.createCertSigned(domain1, 'ferrumgate', 730, false,
        [
            { type: 'domain', value: domain1 },

        ],
        webIntermediate.publicCrt || '', webIntermediate.privateKey);
    return { publicCrt, privateKey, webIntermediate };

}

export async function resetWebCertificate(configService: ConfigService, auditService: AuditService, currentSession: AuthSession, currentUser: User) {
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
    const { publicCrt, privateKey, webIntermediate } = await resetWebCertificateOnly(configService);

    safe.parentId = webIntermediate.id;
    safe.publicCrt = publicCrt;
    safe.privateKey = privateKey;
    safe.updateDate = new Date().toISOString();
    const { before, after } = await configService.setWebSSLCertificate(safe);
    //for audit log
    (before as any).publicCert = cert.publicCrt ? 'a certificate' : null;
    (after as any).publicCert = "new certificate"
    await auditService.logSaveCert(currentSession, currentUser, before, after);
}

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

        await resetWebCertificate(configService, auditService, currentSession, currentUser);
        let ret = await configService.getWebSSLCertificate();
        return res.status(200).json(ret);

    }))

routerPKIAuthenticated.delete('/cert/web/letsencrypt',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete pki web letsencrypt`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const cert = await configService.getWebSSLCertificate();
        if (!cert) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no web cert found');

        cert.letsEncrypt = null;

        cert.updateDate = new Date().toISOString();


        const { publicCrt, privateKey, webIntermediate } = await resetWebCertificateOnly(configService);

        cert.parentId = webIntermediate.id;
        cert.publicCrt = publicCrt;
        cert.privateKey = privateKey;
        cert.updateDate = new Date().toISOString();
        const { before, after } = await configService.setWebSSLCertificate(cert);
        //for audit log
        (before as any).publicCert = cert.publicCrt ? 'a certificate' : null;
        (after as any).publicCert = "new certificate"
        await auditService.logSaveCert(currentSession, currentUser, before, after);

        //always get again, thismakes system more secure, this is a safe function
        const ret = await configService.getWebSSLCertificate();
        return res.status(200).json(ret);


    }))

routerPKIAuthenticated.post('/cert/web/letsencrypt',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`enable pki web letsencrypt and create new cert for web`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const letsEncrypt = appService.letsEncryptService;

        const cert = await configService.getWebSSLCertificate();
        if (!cert) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no web cert found');

        const url = await configService.getUrl();
        const domain = new URL(url).hostname;


        //for testing, we need a server variable
        const server = process.env.LETS_ENCRYPT_SERVER || undefined;
        cert.letsEncrypt = await letsEncrypt.createCertificate(domain, currentUser.username, 'http', server);
        //change current web certificate
        if (cert.letsEncrypt.privateKey && cert.letsEncrypt.publicCrt) {
            cert.privateKey = cert.letsEncrypt.privateKey;
            cert.publicCrt = cert.letsEncrypt.publicCrt;
        }
        if (cert.letsEncrypt.chainCrt) {
            cert.chainCrt = cert.chainCrt;
        }

        cert.updateDate = new Date().toISOString();

        const { before, after } = await configService.setWebSSLCertificate(cert);

        await auditService.logSaveCert(currentSession, currentUser, before, after);

        //always get again, thismakes system more secure, this is a safe function
        const ret = await configService.getWebSSLCertificate();
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
        if (!cert) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrIpIntelligenceSourceNotFound, 'no web cert found');


        const safe = cloneSSlCertificate(input);
        safe.idEx = cert.idEx;
        safe.name = input.name;
        safe.updateDate = new Date().toISOString();
        safe.isEnabled = input.isEnabled ? true : false;
        if (cert.letsEncrypt)
            safe.letsEncrypt = cloneLetsEncrypt(cert.letsEncrypt);

        if (input.privateKey) {
            safe.privateKey = input.privateKey;
            safe.parentId = '';
            safe.publicCrt = input.publicCrt;
        }
        if (input.chainCrt) {
            safe.chainCrt = input.chainCrt
        }
        safe.updateDate = new Date().toISOString();

        const { before, after } = await configService.setWebSSLCertificate(safe);
        if (input.privateKey) {
            //log audit log
            (before as any).publicCert = 'a certificate';
            (after as any).publicCert = "new certificate"
        }
        await auditService.logSaveCert(currentSession, currentUser, before, after);

        //always get again, thismakes system more secure, this is a safe function
        const ret = await configService.getWebSSLCertificate();
        return res.status(200).json(ret);

    }))


















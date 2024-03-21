import express from "express";
import { asyncHandler, logger } from "../common";
import { User } from "../model/user";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { AppService } from "../service/appService";
import { HelperService } from "../service/helperService";
import { Util } from "../util";
import { attachActivity, attachActivityUser, saveActivity, saveActivityError } from "./auth/commonAuth";



export const routerRegister = express.Router();



routerRegister.post('/invite', asyncHandler(async (req: any, res: any, next: any) => {

    try {
        attachActivity(req);
        const userInput = req.body as { key: string, password: string, name?: string };
        if (!userInput.key || !userInput.password)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrUsernameOrPasswordInvalid, "username and password required");



        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const templateService = appService.templateService;
        const emailService = appService.emailService;
        const redisService = appService.redisService;
        const twoFAService = appService.twoFAService;
        const auditService = appService.auditService;
        const sessionService = appService.sessionService;



        const isSystemConfigured = await configService.getIsConfigured();
        if (!isSystemConfigured) {
            logger.warn(`system is not configured yet`);
            throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
        }
        const rKey = `/register/invite/${userInput.key}`;
        const data: { email: string } | null | undefined = await redisService.get(rKey, true);

        if (!data) {
            logger.info('invite key not found');
            throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodes.ErrNotFound, "key not found");
        }



        inputService.checkPasswordPolicy(userInput.password);
        inputService.checkEmail(data.email);//important we need to check,and this must be email
        logger.info(`someone is registering invite from ${req.clientIp} with email: ${data.email}`);
        const userDb = await configService.getUserByUsername(data.email);
        if (userDb) {
            logger.info(`user email ${userDb.username} allready exits sending reset password link`);
            //audit
            req.currentSession = await sessionService.createFakeSession(userDb, false, req.clientIp, userDb.source);
            attachActivityUser(req, userDb);
            //send change password link over email

            const key = Util.createRandomHash(48);
            const link = `${req.baseHost}/user/resetpass?key=${key}`
            await redisService.set(`/user/resetpass/${key}`, userDb.id, { ttl: 7 * 24 * 60 * 60 * 1000 })//1 days

            const logoPath = (await configService.getLogo()).defaultPath || 'logo.png';
            const logo = `${req.baseHost}/dassets/img/${logoPath}`;
            const html = await templateService.createForgotPassword(userDb.name, link, logo);
            //fs.writeFileSync('/tmp/abc.html', html);
            //send reset link over email
            await emailService.send({ to: userDb.username, subject: 'Reset your password', html: html });
            await redisService.delete(rKey);

            await auditService.logResetPassword(req.currentSession, userDb);
            await saveActivity(req, 'register invite');

            return res.status(200).json({ result: true });
        }
        logger.info(`someone is not exits on db with email ${data.email}`);
        let userSave: User = HelperService.createUser('local-local',
            data.email,
            userInput.name || data.email.substring(0, data.email.indexOf('@')),
            userInput.password);

        userSave.isEmailVerified = true;
        userSave.isVerified = true;

        //audit
        req.currentSession = await sessionService.createFakeSession(userSave, false, req.clientIp, userSave.source);
        attachActivityUser(req, userSave);

        await configService.saveUser(userSave);
        await redisService.delete(rKey);


        await auditService.logSaveUser(req.currentSession, userSave, undefined, userSave);
        await saveActivity(req, 'register invite');

        return res.status(200).json({ result: true });
    } catch (err) {
        saveActivityError(req, 'register invite', err);
        throw err;
    }

}));

routerRegister.post('/', asyncHandler(async (req: any, res: any, next: any) => {

    attachActivity(req);
    const userInput = req.body as { username: string, password: string, name?: string };
    if (!userInput.username || !userInput.password)
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrUsernameOrPasswordInvalid, "username and password required");


    const appService = req.appService as AppService;
    const configService = appService.configService;
    const inputService = appService.inputService;
    const templateService = appService.templateService;
    const emailService = appService.emailService;
    const redisService = appService.redisService;
    const twoFAService = appService.twoFAService;
    const auditService = appService.auditService;
    const sessionService = appService.sessionService;



    const isSystemConfigured = await configService.getIsConfigured();
    if (!isSystemConfigured) {
        logger.warn(`system is not configured yet`);
        throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
    }
    const local = await configService.getAuthSettingLocal();
    if (!local.isRegister) {
        logger.warn(`register is not allowed`);
        throw new RestfullException(405, ErrorCodes.ErrMethodNotAllowed, ErrorCodes.ErrMethodNotAllowed, "register not enabled");
    }


    inputService.checkPasswordPolicy(userInput.password);
    inputService.checkEmail(userInput.username);//important we need to check,and this must be email
    logger.info(`someone is registering from ${req.clientIp} with email: ${userInput.username}`);
    const userDb = await configService.getUserByUsername(userInput.username);
    if (userDb) {
        logger.info(`user email ${userDb.username} allready exits sending reset password link`);
        //send change password link over email

        const key = Util.createRandomHash(48);
        const link = `${req.baseHost}/user/resetpass?key=${key}`
        await redisService.set(`/user/resetpass/${key}`, userDb.id, { ttl: 7 * 24 * 60 * 60 * 1000 })//1 days

        const logoPath = (await configService.getLogo()).defaultPath || 'logo.png';
        const logo = `${req.baseHost}/dassets/img/${logoPath}`;
        const html = await templateService.createForgotPassword(userDb.name, link, logo);
        //fs.writeFileSync('/tmp/abc.html', html);
        //send reset link over email
        await emailService.send({ to: userDb.username, subject: 'Reset your password', html: html });


        //audit 
        req.currentSession = await sessionService.createFakeSession(userDb, false, req.clientIp, userDb.source);
        await auditService.logResetPassword(req.currentSession, userDb);
        attachActivityUser(req, userDb);
        await saveActivity(req, 'register');

        return res.status(200).json({ result: true });
    }
    logger.info(`someone is not exits on db with email ${userInput.username}`);
    let userSave: User = HelperService.createUser('local-local',
        userInput.username,
        userInput.name || userInput.username.substring(0, userInput.username.indexOf('@')),
        userInput.password);


    const key = Util.createRandomHash(48);
    const link = `${req.baseHost}/user/confirmemail?key=${key}`
    await redisService.set(`/user/confirm/${key}`, userSave.id, { ttl: 7 * 24 * 60 * 60 * 1000 })//7 days

    const logoPath = (await configService.getLogo()).defaultPath || 'logo.png';
    const logo = `${req.baseHost}/dassets/img/${logoPath}`;
    const html = await templateService.createEmailConfirmation(userSave.name, link, logo);
    //fs.writeFileSync('/tmp/abc.html', html);
    logger.info(`sending email confirm to ${userSave.username}`);
    //send confirmation link over email
    await emailService.send({ to: userSave.username, subject: 'Verify your email', html: html })
    await configService.saveUser(userSave);


    //audit
    req.currentSession = await sessionService.createFakeSession(userSave, false, req.clientIp, userSave.source);
    await auditService.logSaveUser(req.currentSession, userSave, undefined, userSave);
    attachActivityUser(req, userSave);
    await saveActivity(req, 'register');

    return res.status(200).json({ result: true });

}));
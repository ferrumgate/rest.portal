import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { HelperService } from "../service/helperService";

export const routerRegister = express.Router();

routerRegister.post('/', asyncHandler(async (req: any, res: any, next: any) => {
    const userInput = req.body as { username: string, password: string, name?: string };
    if (!userInput.username || !userInput.password)
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, "username and password required");

    const appService = req.appService as AppService;
    const configService = appService.configService;
    const inputService = appService.inputService;
    const templateService = appService.templateService;
    const emailService = appService.emailService;
    const redisService = appService.redisService;
    const twoFAService = appService.twoFAService;


    inputService.checkPasswordPolicy(userInput.password);
    inputService.checkEmail(userInput.username);//important we need to check,and this must be email
    logger.info(`someone is registering from ${req.clientIp} with email: ${userInput.username}`);
    const userDb = await configService.getUserByUsername(userInput.username);
    if (userDb) {
        logger.info(`user email ${userDb.username} allready exits sending reset password link`);
        //send change password link over email

        const key = Util.createRandomHash(48);
        const link = `${req.baseHost}/user/resetpass?key=${key}`
        await redisService.set(`user_resetpass_${key}`, userDb.id, { ttl: 7 * 24 * 60 * 60 * 1000 })//1 days

        const logoPath = (await configService.getLogo()).defaultPath || 'logo.png';
        const logo = `${req.baseHost}/dassets/img/${logoPath}`;
        const html = await templateService.createForgotPassword(userDb.name, link, logo);
        //fs.writeFileSync('/tmp/abc.html', html);
        //send reset link over email
        await emailService.send({ to: userDb.username, subject: 'Reset your password', html: html });
        return res.status(200).json({ result: true });
    }
    logger.info(`someone is not exits on db with email ${userInput.username}`);
    let userSave: User = HelperService.createUser('local',
        userInput.username,
        userInput.name || userInput.username.substr(0, userInput.username.indexOf('@')),
        userInput.password);


    const key = Util.createRandomHash(48);
    const link = `${req.baseHost}/user/emailconfirm?key=${key}`
    await redisService.set(`user_confirm_${key}`, userSave.id, { ttl: 7 * 24 * 60 * 60 * 1000 })//7 days

    const logoPath = (await configService.getLogo()).defaultPath || 'logo.png';
    const logo = `${req.baseHost}/dassets/img/${logoPath}`;
    const html = await templateService.createEmailConfirmation(userSave.name, link, logo);
    //fs.writeFileSync('/tmp/abc.html', html);
    logger.info(`sending email confirm to ${userSave.username}`);
    //send confirmation link over email
    await emailService.send({ to: userSave.username, subject: 'Verify your email', html: html })
    await configService.saveUser(userSave);

    return res.status(200).json({ result: true });

}));
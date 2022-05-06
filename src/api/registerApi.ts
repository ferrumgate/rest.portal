import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';

export const routerRegister = express.Router();

/* 
routerRegister.post('/', asyncHandler(setCacheAndAuth), asyncHandler(authenticate), asyncHandler(authoriseAsUser), asyncHandler(async (req: any, res: any, next: any) => {
    let agents = await getLocation(req);
    return res.status(200).json(agents);

})); */





routerRegister.post('/', asyncHandler(async (req: any, res: any, next: any) => {
    const userInput = req.body;
    if (!userInput.email || !userInput.password)
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, "email and password required");

    const appService = req.appService as AppService;
    const configService = appService.configService;
    const inputService = appService.inputService;
    const templateService = appService.templateService;
    const emailService = appService.emailService;
    const redisService = appService.redisService;



    inputService.checkPasswordPolicy(userInput.password);
    inputService.checkEmail(userInput.email);

    const userDb = await configService.getUserByEmail(userInput.email);
    if (userDb) {
        //send change password link over email

        return res.status(200).json({});
    }
    let userSave: User = {
        email: userInput.email,
        password: Util.bcryptHash(userInput.password),
        groupIds: [],
        id: Util.randomNumberString(16),
        name: userInput.name || userInput.email.substr(0, userInput.email.indexOf('@')),
        source: 'local',
        isVerified: false
    }

    const key = Util.createRandomHash(48);
    const link = `${req.baseHost}/account/confirm/${key}`
    await redisService.set(`account_confirm_${key}`, userSave.id, { ttl: 7 * 24 * 60 * 60 * 1000 })//7 days

    const logoPath = (await configService.getLogo()).defaultPath || 'logo.png';
    const logo = `${req.baseHost}/dassets/img/${logoPath}`;
    const html = await templateService.createEmailConfirmation(userSave.name, link, logo);
    //fs.writeFileSync('/tmp/abc.html', html);
    await emailService.send({ to: userSave.email, subject: 'Verify your email', html: html })
    await configService.saveUser(userSave);

    //send confirmation link over email
    return res.status(200).json({ result: true });

}));
import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import passport from 'passport';

import { checkUser, localInit } from "./auth/local";
import { googleInit } from "./auth/google";
import { linkedinInit } from "./auth/linkedin";





// check if config changed
let lastConfigServiceUpdateTime = '';
async function passportInit(req: any, res: any, next: any) {

    const configService = (req.appService as AppService).configService;
    if (configService.lastUpdateTime != lastConfigServiceUpdateTime) {//if config changed
        const auth = await configService.getAuthOption();
        const domain = await configService.getDomain();
        const url = await configService.getUrl();

        //init local 
        localInit();
        // init google
        if (auth.google) {
            googleInit(auth, url);
        }
        // init linkedin
        if (auth.linkedin) {
            linkedinInit(auth, url);
        }
        lastConfigServiceUpdateTime = configService.lastUpdateTime;

    }
    next();
}

export const routerAuth = express.Router();
async function execute2FA(req: any) {
    const currentUser: User = req.currentUser as User;
    const randomKey = Util.randomNumberString(48);
    const appService = req.appService as AppService;
    const configService = appService.configService;
    const redisService = appService.redisService;
    const twoFAService = appService.twoFAService;
    if (currentUser.is2FA) {
        const rKey = `next_2fa_for_${randomKey}`;
        await redisService.set(rKey, currentUser.id, { ttl: 60 * 1000 });
        return { key: randomKey, twoFAKey: twoFAService.generateSecret() };
    }
    else {
        const rKey = `next_access_for_${randomKey}`;
        await redisService.set(rKey, currentUser.id, { ttl: 60 * 1000 });
        return { key: randomKey };
    }


}
/////////////////////////////////  /auth/local  //////////////////////////////////


routerAuth.post('/local',
    asyncHandler(passportInit),
    passport.authenticate('local', { session: false }),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        logger.info(`authenticated user: ${currentUser.email}`);
        const two2FA = await execute2FA(req);
        return res.status(200).json({ key: two2FA.key, is2FA: currentUser.is2FA || false, twoFASecret: two2FA.twoFAKey });
    })
);



/////////////////////////// /auth/google //////////////////////////


routerAuth.use('/google/callback',
    asyncHandler(passportInit),
    passport.authenticate('google', { session: false }),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        logger.info(`authenticated user: ${currentUser.email}`);
        const two2FA = await execute2FA(req);
        return res.status(200).json({ key: two2FA.key, is2FA: currentUser.is2FA || false, twoFASecret: two2FA.twoFAKey });
    })
);

routerAuth.get('/google',
    asyncHandler(passportInit),
    passport.authenticate('google', { session: false, }),
    asyncHandler(async (req: any, res: any, next: any) => {

        return res.status(200).json({});
    })
);



/////////////////////////// /auth/linkedin //////////////////////////


routerAuth.use('/linkedin/callback',
    asyncHandler(passportInit),
    passport.authenticate('linkedin', { session: false }),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        logger.info(`authenticated user: ${currentUser.email}`);
        const two2FA = await execute2FA(req);
        return res.status(200).json({ key: two2FA.key, is2FA: currentUser.is2FA || false, twoFASecret: two2FA.twoFAKey });
    })
);

routerAuth.get('/linkedin',
    asyncHandler(passportInit),
    passport.authenticate('linkedin', { session: false, }),
    asyncHandler(async (req: any, res: any, next: any) => {

        return res.status(200).json({});
    })
);



///////////////////////// /auth/2fa     ////////////////////////////////


routerAuth.post('/2fa',
    asyncHandler(async (req: any, res: any, next: any) => {

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const redisService = appService.redisService;
        const twoFAService = appService.twoFAService;

        const request = req.body as { key: string, twoFASecret: string, twoFAToken: string };
        if (!request.key || !request.twoFASecret || !request.twoFAToken)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, "needs key, 2FASecret and 2FAToken");
        logger.info(`2fa check with key:${request.key}`);

        twoFAService.verifyToken(request.twoFASecret, request.twoFAToken);
        const rKey = `next_2fa_for_${request.key}`;
        const userId = await redisService.get(rKey, false) as string;
        if (!userId)
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, 'key not found');

        const user = await configService.getUserById(userId);
        if (!user) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'not authorized');
        checkUser(user);
        const randomKey = Util.randomNumberString(48);
        const key = `next_access_for_${randomKey}`;
        await redisService.set(key, user.id, { ttl: 60 * 1000 });
        return res.status(200).json({ key: randomKey });

    })
);





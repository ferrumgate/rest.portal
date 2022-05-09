import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import passport from 'passport';

import { localInit } from "./auth/local";
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
    if (currentUser.is2FA) {
        const rKey = `next_2fa_for_${randomKey}`;
        await redisService.set(rKey, currentUser.id, { ttl: 60 * 1000 });
    }
    else {
        const rKey = `next_access_for_${randomKey}`;
        await redisService.set(rKey, currentUser.id, { ttl: 60 * 1000 });
    }
    return randomKey;
}
/////////////////////////////////  /auth/local  //////////////////////////////////


routerAuth.post('/local',
    asyncHandler(passportInit),
    passport.authenticate('local', { session: false }),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        const randomKey = await execute2FA(req);
        return res.status(200).json({ key: randomKey, is2FA: currentUser.is2FA || false, twoFAType: currentUser.twoFAType });
    })
);


/////////////////////////// /auth/google //////////////////////////


routerAuth.use('/google/callback',
    asyncHandler(passportInit),
    passport.authenticate('google', { session: false }),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        const randomKey = await execute2FA(req);
        return res.status(200).json({ key: randomKey, is2FA: currentUser.is2FA || false, twoFAType: 'google' });
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
        const randomKey = await execute2FA(req);
        return res.status(200).json({ key: randomKey, is2FA: currentUser.is2FA || false, twoFAType: 'google' });
    })
);

routerAuth.get('/linkedin',
    asyncHandler(passportInit),
    passport.authenticate('linkedin', { session: false, }),
    asyncHandler(async (req: any, res: any, next: any) => {

        return res.status(200).json({});
    })
);




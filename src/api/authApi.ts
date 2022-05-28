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
import { HelperService } from "../service/helperService";
import { apiKeyInit } from "./auth/apikey";
import { jwtInit } from "./auth/jwt";
import { passportInit } from "./auth/passportInit";







export const routerAuth = express.Router();
async function execute2FA(req: any) {
    const currentUser: User = req.currentUser as User;
    const randomKey = Util.randomNumberString(48);
    const appService = req.appService as AppService;
    const configService = appService.configService;
    const redisService = appService.redisService;
    const twoFAService = appService.twoFAService;
    const sensitiveData = await configService.getUserSensitiveData(currentUser.id);
    if (currentUser.is2FA && sensitiveData.twoFASecret) {
        const rKey = `/2fa/${randomKey}`;
        await redisService.set(rKey, currentUser.id, { ttl: 60 * 1000 });
        return { key: randomKey };
    }
    else {
        const rKey = `/access/${randomKey}`;
        await redisService.set(rKey, currentUser.id, { ttl: 60 * 1000 });
        return { key: randomKey };
    }


}
/////////////////////////////////  /auth/local  //////////////////////////////////


routerAuth.post('/local',
    asyncHandler(passportInit),
    passport.authenticate(['local', 'headerapikey'], { session: false }),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        logger.info(`authenticated user: ${currentUser.username}`);
        const two2FA = await execute2FA(req);
        return res.status(200).json({ key: two2FA.key, is2FA: currentUser.is2FA || false });
    })
);



/////////////////////////// /auth/google //////////////////////////


routerAuth.use('/google/callback',
    asyncHandler(passportInit),
    passport.authenticate('google', { session: false }),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        logger.info(`authenticated user: ${currentUser.username}`);
        const two2FA = await execute2FA(req);
        return res.status(200).json({ key: two2FA.key, is2FA: currentUser.is2FA || false });
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
        logger.info(`authenticated user: ${currentUser.username}`);
        const two2FA = await execute2FA(req);
        return res.status(200).json({ key: two2FA.key, is2FA: currentUser.is2FA || false });
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

        const request = req.body as { key: string, twoFAToken: string };
        if (!request.key || !request.twoFAToken)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, "needs key, 2FASecret and 2FAToken");
        logger.info(`2fa check with key:${request.key}`);

        const rKey = `/2fa/${request.key}`;
        const userId = await redisService.get(rKey, false) as string;
        if (!userId)
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, 'key not found');

        const user = await configService.getUserById(userId);
        if (!user) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'not authorized');
        HelperService.isValidUser(user);
        const sensitiveData = await configService.getUserSensitiveData(userId);
        twoFAService.verifyToken(sensitiveData.twoFASecret || '', request.twoFAToken);

        const randomKey = Util.randomNumberString(48);
        const key = `/access/${randomKey}`;
        await redisService.set(key, user.id, { ttl: 60 * 1000 });
        return res.status(200).json({ key: randomKey });

    })
);

/////////////////////////////// /authaccesstoken ///////////////////////////////

routerAuth.post('/accesstoken',
    asyncHandler(async (req: any, res: any, next: any) => {

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const redisService = appService.redisService;
        const oauth2Service = appService.oauth2Service;
        const request = req.body as { key: string };
        if (!request.key) {
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, "needs parameters");
        }
        logger.info(`getting access token with key ${request.key}`);
        const key = `/access/${request.key}`;
        const userId = await redisService.get(key, false) as string;
        if (!userId) {
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, "not authorized");
        }

        const user = await configService.getUserById(userId);
        await HelperService.isValidUser(user);
        //set user to request object
        req.currentUser = user;
        if (!user?.id) {
            throw new RestfullException(500, ErrorCodes.ErrInternalError, "something went wrong");
        }


        const accessTokenStr = await oauth2Service.generateAccessToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: user.id }, 'ferrum')
        const accessToken = await oauth2Service.getAccessToken(accessTokenStr);
        const refreshTokenStr = await oauth2Service.generateRefreshToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: user.id }, 'ferrum');
        const refreshToken = await oauth2Service.getRefreshToken(refreshTokenStr);
        await redisService.delete(key);

        return res.status(200).json({ ...accessToken, ...refreshToken });
    })
);


/////////////////////////////// /auth/refreshtoken ///////////////////////////////

routerAuth.post('/refreshtoken',
    asyncHandler(passportInit),
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req: any, res: any, next: any) => {

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const redisService = appService.redisService;
        const oauth2Service = appService.oauth2Service;
        const request = req.body as { refreshToken: string };
        if (!request.refreshToken) {
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, "needs parameters");
        }
        logger.info(`getting refresh token with key ${request.refreshToken}`);

        const inputRefreshToken = await oauth2Service.getRefreshToken(request.refreshToken);
        if (!inputRefreshToken)
            throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, "jwt verification failed");

        const userId = inputRefreshToken.user.id;

        //checkuser
        const user = await configService.getUserById(userId);
        await HelperService.isValidUser(user);
        if (!user)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, "not authorized");
        //check also currentUser that comes from accessToken
        if (req.currentUser.id != user.id)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, "not authorized");


        //set user to request object
        req.currentUser = user;
        if (!user?.id) {
            throw new RestfullException(500, ErrorCodes.ErrInternalError, "something went wrong");
        }


        const accessTokenStr = await oauth2Service.generateAccessToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: user.id }, 'ferrum')
        const accessToken = await oauth2Service.getAccessToken(accessTokenStr);
        const refreshTokenStr = await oauth2Service.generateRefreshToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: user.id }, 'ferrum');
        const refreshToken = await oauth2Service.getRefreshToken(refreshTokenStr);


        return res.status(200).json({ ...accessToken, ...refreshToken });
    })
);


routerAuth.post('/token/test',
    asyncHandler(passportInit),
    passport.authenticate(['headerapikey', 'jwt'], { session: false }),
    asyncHandler(async (req: any, res: any, next: any) => {
        return res.status(200).json({ works: true });
    })
);


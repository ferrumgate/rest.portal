import express from "express";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import passport from 'passport';

import { localInit } from "./auth/local";
import { oauthGoogleInit } from "./auth/google";
import { oauthLinkedinInit } from "./auth/linkedin";
import { HelperService } from "../service/helperService";
import { apiKeyInit } from "./auth/apikey";
import { jwtInit } from "./auth/jwt";
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import cors from 'cors';
import { corsOptionsDelegate } from "./cors";
import { stringify } from "querystring";
import { userInfo } from "os";
import { AuthSession } from "../model/authSession";
import { attachActivity, attachActivitySession, attachActivityUser, attachActivityUsername, saveActivity, saveActivityError } from "./auth/commonAuth";
import { Countries } from "../model/country";








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
        const rKey = `/auth/2fa/${randomKey}`;
        await redisService.set(rKey, { userId: currentUser.id, activity: req.activity }, { ttl: 60 * 1000 });
        return { key: randomKey };
    }
    else {
        const rKey = `/auth/access/${randomKey}`;
        await redisService.set(rKey, { userId: currentUser.id, is2FA: false, activity: req.activity }, { ttl: 60 * 1000 });
        return { key: randomKey };
    }


}

/////////////////////////////////  /auth/start  //////////////////////////////////


routerAuth.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['local', 'headerapikey', 'activedirectory']),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        logger.info(`authenticated user: ${currentUser.username}`);
        const two2FA = await execute2FA(req);
        return res.status(200).json({ key: two2FA.key, is2FA: currentUser.is2FA || false });
    })
);

/////////////////////////// /auth/google //////////////////////////


routerAuth.use('/oauth/google/callback',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['google']),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        logger.info(`authenticated user: ${currentUser.username}`);
        const two2FA = await execute2FA(req);
        return res.status(200).json({ key: two2FA.key, is2FA: currentUser.is2FA || false });
    })
);


routerAuth.get('/oauth/google',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['google']),
    asyncHandler(async (req: any, res: any, next: any) => {

        return res.status(200).json({});
    })
);



/////////////////////////// /auth/linkedin //////////////////////////


routerAuth.use('/oauth/linkedin/callback',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['linkedin']),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        logger.info(`authenticated user: ${currentUser.username}`);
        const two2FA = await execute2FA(req);
        return res.status(200).json({ key: two2FA.key, is2FA: currentUser.is2FA || false });
    })
);

routerAuth.get('/oauth/linkedin',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['linkedin']),
    asyncHandler(async (req: any, res: any, next: any) => {

        return res.status(200).json({});
    })
);


/////////////////////////// /auth/auth0 //////////////////////////


routerAuth.use('/saml/auth0/callback',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['auth0']),
    asyncHandler(async (req: any, res: any, next: any) => {

        const currentUser: User = req.currentUser as User;
        logger.info(`authenticated user: ${currentUser.username}`);
        const two2FA = await execute2FA(req);
        const obj = { key: two2FA.key, is2FA: currentUser.is2FA ? 'true' : 'false' };
        const query = new URLSearchParams(obj);


        return res.redirect(`/login/callback/saml/auth0?${query.toString()}`)
    })
);

routerAuth.get('/saml/auth0',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['auth0']),
    asyncHandler(async (req: any, res: any, next: any) => {

        return res.status(200).json({});
    })
);







///////////////////////// /auth/2fa     ////////////////////////////////


routerAuth.post('/2fa',
    asyncHandler(async (req: any, res: any, next: any) => {
        try {
            const appService = req.appService as AppService;
            const configService = appService.configService;
            const redisService = appService.redisService;
            const twoFAService = appService.twoFAService;

            const request = req.body as { key: string, twoFAToken: string };
            if (!request.key || !request.twoFAToken)
                throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "needs key, 2FASecret and 2FAToken");
            logger.info(`2fa check with key:${request.key}`);

            const rKey = `/auth/2fa/${request.key}`;
            const { userId, activity } = await redisService.get(rKey) as { userId: string, activity: any };
            if (!userId)
                throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrKeyNotFound, 'key not found');
            //save some data for activitiy
            attachActivity(req, activity);
            const user = await configService.getUserById(userId);
            if (!user) throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrUserNotFound, 'not authenticated');
            attachActivityUser(req, user);
            HelperService.isValidUser(user);

            const sensitiveData = await configService.getUserSensitiveData(userId);
            twoFAService.verifyToken(sensitiveData.twoFASecret || '', request.twoFAToken);

            const randomKey = Util.randomNumberString(48);
            const key = `/auth/access/${randomKey}`;
            await redisService.set(key, { userId: user.id, activity: req.activity, is2FA: true }, { ttl: 60 * 1000 });

            await saveActivity(req, '2fa check', (log) => { log.is2FA = true; });
            return res.status(200).json({ key: randomKey });


        } catch (err) {
            await saveActivityError(req, '2fa check', err);
            throw err;
        }

    })

);

/////////////////////////////// /auth/accesstoken ///////////////////////////////




routerAuth.post('/accesstoken',
    asyncHandler(async (req: any, res: any, next: any) => {
        try {
            const appService = req.appService as AppService;
            const configService = appService.configService;
            const redisService = appService.redisService;
            const oauth2Service = appService.oauth2Service;
            const tunnelService = appService.tunnelService;
            const policyService = appService.policyService;
            const sessionService = appService.sessionService;
            const inputService = appService.inputService;
            const systemlogService = appService.systemLogService;
            const ipIntelligenceService = appService.ipIntelligenceService;
            //tunnel field is the tunnel tunnel key
            const request = req.body as { key: string, exchangeKey?: string };
            if (!request.key) {
                throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "needs parameters");
            }
            logger.info(`getting access token with key ${request.key}`);
            const key = `/auth/access/${request.key}`;
            const access = await redisService.get<{ userId: string, is2FA: boolean, activity: any }>(key, true);
            if (!access || !access.userId) {
                throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrKeyNotFound, "not authorized");
            }
            attachActivity(req, access?.activity);

            const user = await configService.getUserById(access.userId);
            attachActivityUser(req, user);
            await HelperService.isValidUser(user);
            //set user to request object
            req.currentUser = user;
            if (!user?.id) {
                throw new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodes.ErrInternalError, "something went wrong");
            }

            // ip intelligence
            //if ip is not local ip, then get ip intelligence data
            const ipIntel = await ipIntelligenceService.query(req.clientIp);


            //create a session
            const authSession = await sessionService.createSession(req.currentUser, access.is2FA, req.clientIp, req.activity?.authSource || 'unknown',
                ipIntel?.countryCode, ipIntel?.countryName, ipIntel?.isProxy, ipIntel?.isHosting, ipIntel?.isCrawler);
            await systemlogService.write({ path: '/system/sessions/create', type: 'put', val: authSession });
            req.currentSession = authSession;
            attachActivitySession(req, authSession);
            //attachActivityTunnelId(req, request.tunnelKey);
            //check tunnel session
            //TODO disable tunnel keys for access tokens
            /*  if (request.tunnelKey) {
                 //check if user can authenticate to this network
 
                 //check policy authentication
                 await policyService.authenticate(user, access.is2FA, request.tunnelKey);
                 await tunnelService.createTunnel(user, request.tunnelKey);
                 //TODO add this to tunnel list
             } */


            const accessTokenStr = await oauth2Service.generateAccessToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: user.id, sid: authSession.id }, 'ferrum')
            const accessToken = await oauth2Service.getAccessToken(accessTokenStr);
            const refreshTokenStr = await oauth2Service.generateRefreshToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: user.id, sid: authSession.id }, 'ferrum');
            const refreshToken = await oauth2Service.getRefreshToken(refreshTokenStr);
            await redisService.delete(key);

            if (request.exchangeKey) {
                const exKey = Util.decrypt(configService.getEncKey(), request.exchangeKey);
                const key = `/exchange/id/${exKey}`
                await redisService.set(key, authSession.id, { ttl: 60 * 1000 });//1 minute exchange key

            }

            await saveActivity(req, 'access token', (log) => {
                log.sessionId = authSession.id;

            });

            return res.status(200).json({ ...accessToken, ...refreshToken });
        } catch (err) {

            await saveActivityError(req, 'access token', err, (log) => {
                log.sessionId = req.activity.sessionId;
                log.tunnelId = req.activity.tunnelId;
            });
            throw err;
        }
    })
);


/////////////////////////////// /auth/refreshtoken ///////////////////////////////

routerAuth.post('/refreshtoken',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt']),
    asyncHandler(async (req: any, res: any, next: any) => {
        try {
            const appService = req.appService as AppService;
            const configService = appService.configService;
            const redisService = appService.redisService;
            const oauth2Service = appService.oauth2Service;
            const sessionService = appService.sessionService;
            const systemlogService = appService.systemLogService;
            const request = req.body as { refreshToken: string };
            if (!request.refreshToken) {
                throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "needs parameters");
            }
            logger.info(`getting refresh token with key ${request.refreshToken.substring(0, 6)}`);

            const inputRefreshToken = await oauth2Service.getRefreshToken(request.refreshToken);
            if (!inputRefreshToken)
                throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, ErrorCodes.ErrJWTVerifyFailed, "jwt verification failed");

            const userId = inputRefreshToken.user.id;
            const sessionId = inputRefreshToken.user.sid;
            attachActivitySession(req, { id: sessionId } as AuthSession);
            //checkuser
            const user = await configService.getUserById(userId);
            attachActivityUser(req, user);

            await HelperService.isValidUser(user);
            if (!user)
                throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrUserNotFound, "not authenticated");
            //check also currentUser that comes from accessToken
            if (req.currentUser.id != user.id)
                throw new RestfullException(401, ErrorCodes.ErrDataVerifyFailed, ErrorCodes.ErrDataVerifyFailed, "not authenticated");


            //set user to request object
            req.currentUser = user;
            if (!user?.id) {
                throw new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodes.ErrInternalError, "something went wrong");
            }

            //check session
            const sid = inputRefreshToken.user.sid;
            const authSession = await sessionService.getSession(sid);
            attachActivitySession(req, authSession);

            if (!authSession || authSession.userId != user.id)
                throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrSessionNotFound, "not authenticated");

            await sessionService.setSession(sid, { lastSeen: new Date().toISOString() })
            await sessionService.setExpire(sid);
            await systemlogService.write({ path: '/system/sessions/alive', type: 'put', val: authSession });

            const accessTokenStr = await oauth2Service.generateAccessToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: user.id, sid: authSession.id }, 'ferrum')
            const accessToken = await oauth2Service.getAccessToken(accessTokenStr);
            const refreshTokenStr = await oauth2Service.generateRefreshToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: user.id, sid: authSession.id }, 'ferrum');
            const refreshToken = await oauth2Service.getRefreshToken(refreshTokenStr);

            //await saveActivity(req, 'refresh token'); // no need to save
            return res.status(200).json({ ...accessToken, ...refreshToken });
        } catch (err) {
            await saveActivityError(req, 'refresh token', err);
            throw err;
        }
    })
);

routerAuth.get('/exchangetoken',
    asyncHandler(async (req: any, res: any, next: any) => {
        try {
            const appService = req.appService as AppService;
            const configService = appService.configService;
            const redisService = appService.redisService;
            const oauth2Service = appService.oauth2Service;
            const sessionService = appService.sessionService;
            logger.info(`get exchange token`);
            const str = Util.encrypt(configService.getEncKey(), Util.randomNumberString(128));
            return res.status(200).json({ token: str });
        } catch (err) {
            await saveActivityError(req, 'exchange token', err);
            throw err;
        }
    })
);

routerAuth.post('/exchangetoken',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['exchangeKey']),
    asyncHandler(async (req: any, res: any, next: any) => {
        try {
            const appService = req.appService as AppService;
            const configService = appService.configService;
            const redisService = appService.redisService;
            const oauth2Service = appService.oauth2Service;
            const sessionService = appService.sessionService;

            logger.info(`exchange token ${req.exchangeToken}`);

            const user = req.currentUser as User;
            const authSession = req.currentSession as AuthSession;

            const accessTokenStr = await oauth2Service.generateAccessToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: user.id, sid: authSession.id }, 'ferrum')
            const accessToken = await oauth2Service.getAccessToken(accessTokenStr);
            const refreshTokenStr = await oauth2Service.generateRefreshToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: user.id, sid: authSession.id }, 'ferrum');
            const refreshToken = await oauth2Service.getRefreshToken(refreshTokenStr);

            return res.status(200).json({ ...accessToken, ...refreshToken });
        } catch (err) {
            await saveActivityError(req, 'exchange token', err);
            throw err;
        }
    })
);


routerAuth.post('/token/test',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['headerapikey', 'jwt']),
    asyncHandler(async (req: any, res: any, next: any) => {
        return res.status(200).json({ works: true });
    })
);




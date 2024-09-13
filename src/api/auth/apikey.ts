import passport from 'passport';
import * as passportapikey from 'passport-headerapikey';
import { logger } from '../../common';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../../restfullException';
import { AppService } from '../../service/appService';
import { HelperService } from '../../service/helperService';
import { attachActivitySession, attachActivitySource, attachActivityUser, attachActivityUsername, saveActivity, saveActivityError } from './commonAuth';

const name = 'headerapikey';
export function apiKeyInit() {
    passport.use(new passportapikey.HeaderAPIKeyStrategy(
        {
            header: 'ApiKey', prefix: '',

        }, true,
        async (apikey: string, done: any, req: any) => {
            try {

                attachActivitySource(req, name);
                logger.info(`passport local with apikey: ${apikey.substring(0, 10)}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const sessionService = appService.sessionService;

                if (!apikey)
                    throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "bad argument");
                const userId = apikey.slice(0, 16);

                //const user = await configService.getUserByApiKey(apikey);
                const user = await configService.getUserById(userId);


                attachActivityUser(req, user);
                attachActivityUsername(req, user?.username);
                HelperService.isValidUser(user);
                const sensitiveData = await configService.getUserSensitiveData(userId);
                if (sensitiveData?.apiKey?.key != apikey) {
                    throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrUserNotFound, 'not found');
                }
                //set user to request object
                req.currentUser = user;

                // TODO we need session
                if (user)
                    req.currentSession = await sessionService.createFakeSession(user, false, req.clientIp, name);

                attachActivitySession(req, req.currentSession);

                await saveActivity(req, 'login try');
                return done(null, user);

            } catch (err) {
                await saveActivityError(req, 'login try', err);
                return done(null, null, err);
            }

        }
    ));
    return name;
}

export function apiKeyUnuse() {
    return passport.unuse(name);
}

import passport from 'passport';
import * as passportapikey from 'passport-headerapikey';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { ErrorCodes, RestfullException } from '../../restfullException';
import { HelperService } from '../../service/helperService';
import { Util } from '../../util';
import { attachActivitySource, attachActivityUser, attachActivityUsername, saveActivity, saveActivityError } from './commonAuth';

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
                const user = await configService.getUserByApiKey(apikey);

                attachActivityUser(req, user);
                attachActivityUsername(req, user?.username);
                HelperService.isValidUser(user);
                //set user to request object
                req.currentUser = user;

                // TODO we need session
                if (user)
                    req.currentSession = await sessionService.createFakeSession(user, false, req.clientIp, name);

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
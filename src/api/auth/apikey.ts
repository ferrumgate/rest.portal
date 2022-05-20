
import passport from 'passport';
import * as passportapikey from 'passport-headerapikey';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { ErrorCodes, RestfullException } from '../../restfullException';
import { HelperService } from '../../service/helperService';

export function apiKeyInit() {
    passport.use(new passportapikey.HeaderAPIKeyStrategy(
        {
            header: 'ApiKey', prefix: '',

        }, true,
        async (apikey: string, done: any, req: any) => {
            try {
                logger.info(`passport local with apikey: ${apikey.substring(0, 10)}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;

                if (!apikey)
                    throw new RestfullException(400, ErrorCodes.ErrBadArgument, "bad argument");
                const user = await configService.getUserByApiKey(apikey);
                await HelperService.isValidUser(user);
                //set user to request object
                req.currentUser = user;
                return done(null, user);

            } catch (err) {
                return done(err);
            }

        }
    ));
}
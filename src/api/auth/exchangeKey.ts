
import passport from 'passport';
import * as passportapikey from 'passport-headerapikey';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../../restfullException';
import { HelperService } from '../../service/helperService';
import { Tunnel } from '../../model/tunnel';
import passportCustom from 'passport-custom';
import { attachActivitySession, attachActivitySessionId, attachActivitySource, attachActivityUser, attachActivityUsername, saveActivity, saveActivityError } from './commonAuth';
import { ActivityLog } from '../../model/activityLog';
import { Util } from '../../util';


const name = 'exchangeKey';
export function exchangeKeyInit() {
    passport.use(name, new passportCustom.Strategy(
        async (req: any, done: any) => {
            //logs show too much error, we are trying to handle this valid tries
            let needToSaveActivityError = true;
            try {

                attachActivitySource(req, name);
                let exchangeKeyEnc = req.get('ExchangeKey') as string || req.query.exchangeKey || req.body.exchangeKey;

                if (!exchangeKeyEnc)
                    throw new RestfullException(401, ErrorCodes.ErrExchangeKeyIsNotValid, ErrorCodes.ErrExchangeKeyIsNotValid, 'exchange key not found');
                attachActivityUsername(req, exchangeKeyEnc);
                logger.info(`passport with exchangekey: ${exchangeKeyEnc}`);

                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const tunnelService = appService.tunnelService;
                const sessionService = appService.sessionService;

                const exchangeKey = Util.decrypt(configService.getEncKey(), exchangeKeyEnc)

                //key decrypted, check if too much try occured, client checks every 2 seconds
                try {
                    needToSaveActivityError = false;
                    await appService.rateLimit.check(req.clientIp, `exchange/id/${exchangeKey}`, 5);
                } catch (ignored) {
                    //too much tried
                    needToSaveActivityError = true;
                }

                const sessionKey = await redisService.get(`/exchange/id/${exchangeKey}`, false) as string;
                if (!sessionKey)
                    throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrKeyNotFound, "invalid key");
                const currentSession = await sessionService.getSession(sessionKey);
                if (!currentSession)
                    throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrSessionNotFound, "invalid key");


                req.currentSession = currentSession;
                attachActivitySession(req, currentSession);
                //set user to request object
                const user = await configService.getUserById(currentSession.userId || '0');
                attachActivityUser(req, user);
                HelperService.isValidUser(user);
                req.currentUser = user;
                req.exchangeToken = exchangeKey;
                await redisService.delete(`/exchange/id/${exchangeKey}`);
                await saveActivity(req, 'login try');
                return done(null, user);

            } catch (err) {
                if (needToSaveActivityError)
                    await saveActivityError(req, 'login try', err);
                return done(null, null, err);
            }

        }
    ));
    return name;
}
export function exchangeKeyUnuse() {
    passport.unuse(name)
}
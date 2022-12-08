import passportCustom from 'passport-custom';
import passport from 'passport';
import passportlocal from 'passport-local';
import passportgoogle from 'passport-google-oauth2';
import { AuthSettings } from '../../model/authSettings';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { User } from '../../model/user';
import { Util } from '../../util';
import { ErrorCodes, RestfullException } from '../../restfullException';
import { HelperService } from '../../service/helperService';
import { attachActivitySession, attachActivitySessionId, attachActivitySource, attachActivityUser, saveActivity, saveActivityError } from './commonAuth';

const name = 'jwt';
export function jwtInit() {
    passport.use(name, new passportCustom.Strategy(
        async (req: any, done: any) => {
            try {

                attachActivitySource(req, name);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const oauth2Service = appService.oauth2Service;
                const sessionService = appService.sessionService;

                let authorizationHeader = req.get('Authorization') as string;
                if (!authorizationHeader)
                    throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, ErrorCodes.ErrJWTVerifyFailed, 'jwt header not found');
                if (authorizationHeader.indexOf("Bearer") < 0)
                    throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, ErrorCodes.ErrJWTVerifyFailed, 'jwt header not found');
                authorizationHeader = authorizationHeader.replace('Bearer', '').trim();

                const token = await oauth2Service.getAccessToken(authorizationHeader);
                if (!token)
                    throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, ErrorCodes.ErrJWTVerifyFailed, 'jwt header not found');

                const userId = token.user.id;
                const sid = token.user.sid;
                attachActivitySession(req, { id: sid } as any);
                const currentSession = await sessionService.getSession(sid);
                req.currentSession = currentSession;
                attachActivitySession(req, currentSession);

                const user = await configService.getUserById(userId);
                attachActivityUser(req, user);
                HelperService.isValidUser(user);
                //set user to request object
                req.currentUser = user;

                //await saveActivity(req, 'token verify');
                return done(null, user);

            } catch (err) {
                await saveActivityError(req, 'token verify', err);
                return done(null, null, err);
            }

        }

    ));
    return name;
}

export function jwtUnuse() {
    passport.unuse(name);
}
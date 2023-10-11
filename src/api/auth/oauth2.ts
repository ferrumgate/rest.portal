/* 
import passport from 'passport';
import passportlocal from 'passport-local';
import passportgoogle from 'passport-google-oauth2';
import { AuthOAuth, AuthSettings, BaseOAuth } from '../../model/authSettings';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { User } from '../../model/user';
import { Util } from '../../util';
import { HelperService } from '../../service/helperService';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../../restfullException';
import { attachActivitySource, attachActivityUser, attachActivityUsername, checkUser, saveActivity, saveActivityError } from './commonAuth';
import * as passportoauth2 from 'passport-oauth2';
import Axios from 'axios';


export function oauth2Init(auth: BaseOAuth, url: string) {
    if (!auth.authName)
        throw new RestfullException(500, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "open id needs an auth name");
    const name = auth.authName;
    passport.use(name, new passportoauth2.Strategy({
        authorizationURL: auth.authorizationUrl || '',
        tokenURL: auth.tokenUrl || '',
        clientID: auth.clientId || '',
        clientSecret: auth.clientSecret || '',
        callbackURL: `${url}/login/callback/oauth/${name}`,
        passReqToCallback: true,
        scope: ['email', 'profile', 'openid'],
    },
        async (req: any, accessToken: any, refreshToken: any, profile: any, done: any) => {

            try {
                const profile2 = await Axios.get('https://www.googleapis.com/oauth2/v3/userinfo?access_token=' + accessToken);
                const body = profile2.data;
                attachActivitySource(req, name);

                const email = profile.email;
                attachActivityUsername(req, email);
                const uname = profile.displayName || profile.name;
                logger.info(`passport google with email: ${email}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const source = `${auth.baseType}-${auth.type}`;
                if (!auth.isEnabled)
                    throw new RestfullException(401, ErrorCodes.ErrDisabledSource, ErrorCodes.ErrDisabledSource, 'disabled source');
                let user = await configService.getUserByUsername(email);
                if (!user) {
                    if (!auth.saveNewUser)
                        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrSaveNewUserDisabled, "new user save invalid");
                    let userSave: User = HelperService.createUser(source, email, uname, '');
                    userSave.isVerified = true;
                    await configService.saveUser(userSave);
                    //get back
                    user = await configService.getUserByUsername(email);
                    attachActivityUser(req, user);

                } else {
                    attachActivityUser(req, user);
                    await checkUser(user, auth);
                }

                //set user to request object
                req.currentUser = user;
                await saveActivity(req, 'login try');
                return done(null, user);

            } catch (err) {
                await saveActivityError(req, 'login try', err);
                return done(err);
            }
        }
    ));
    return name;
}

export function oauth2Unuse(name: string) {
    passport.unuse(name);
} */
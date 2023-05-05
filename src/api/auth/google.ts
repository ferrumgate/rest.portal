
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


const name = 'google';
export function oauthGoogleInit(google: BaseOAuth, url: string) {
    //const google = auth.oauth?.providers.find(x => x.type == 'google')
    passport.use(new passportgoogle.Strategy({
        clientID: google.clientId || '',
        clientSecret: google.clientSecret || '',
        callbackURL: `${url}/login/callback/oauth/google`,
        passReqToCallback: true,
        scope: ['email', 'profile', 'openid'],
    },
        async (req: any, accessToken: any, refreshToken: any, profile: any, done: any) => {

            try {

                attachActivitySource(req, name);

                const email = profile.email;
                attachActivityUsername(req, email);
                const uname = profile.displayName;
                logger.info(`passport google with email: ${email}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const source = `${google.baseType}-${google.type}`;
                if (!google.isEnabled)
                    throw new RestfullException(401, ErrorCodes.ErrDisabledSource, ErrorCodes.ErrDisabledSource, 'disabled source');
                let user = await configService.getUserByUsername(email);
                if (!user) {
                    if (!google.saveNewUser)
                        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrSaveNewUserDisabled, "new user save invalid");
                    let userSave: User = HelperService.createUser(source, email, uname, '');
                    userSave.isVerified = true;
                    await configService.saveUser(userSave);
                    //get back
                    user = await configService.getUserByUsername(email);
                    attachActivityUser(req, user);

                } else {
                    attachActivityUser(req, user);
                    await checkUser(user, google);
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

export function oauthGoogleUnuse() {
    passport.unuse(name);
}
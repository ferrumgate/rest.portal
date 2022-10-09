
import passport from 'passport';
import passportlocal from 'passport-local';
import passportgoogle from 'passport-google-oauth2';
import { AuthOAuth, AuthSettings, BaseOAuth } from '../../model/authSettings';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { User } from '../../model/user';
import { Util } from '../../util';
import { HelperService } from '../../service/helperService';
import { ErrorCodes, RestfullException } from '../../restfullException';
import { checkUser } from './commonAuth';



export function oauthGoogleInit(google: BaseOAuth, url: string) {
    //const google = auth.oauth?.providers.find(x => x.type == 'google')
    passport.use(new passportgoogle.Strategy({
        clientID: google?.clientId || '',
        clientSecret: google?.clientSecret || '',
        callbackURL: `${url}/login/callback/google`,
        passReqToCallback: true,
        scope: ['email', 'profile', 'openid'],
    },
        async (req: any, accessToken: any, refreshToken: any, profile: any, done: any) => {
            try {
                const email = profile.email;
                const name = profile.displayName;
                logger.info(`passport google with email: ${email}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const source = `${google.baseType}-${google.type}`;
                if (!google.isEnabled)
                    throw new RestfullException(401, ErrorCodes.ErrDisabledSource, 'disabled source');
                let user = await configService.getUserByUsername(email);
                if (!user) {
                    let userSave: User = HelperService.createUser(source, email, name, '');
                    userSave.isVerified = true;
                    await configService.saveUser(userSave);

                } else {
                    await checkUser(user, google);
                }

                //set user to request object
                req.currentUser = user;
                return done(null, user);

            } catch (err) {
                return done(err);
            }
        }
    ));
}
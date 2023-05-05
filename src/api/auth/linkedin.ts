
import passport from 'passport';
import passportlocal from 'passport-local';
import passportlinkedin from 'passport-linkedin-oauth2';
import { AuthSettings, BaseOAuth } from '../../model/authSettings';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { User } from '../../model/user';
import { Util } from '../../util';
import { HelperService } from '../../service/helperService';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../../restfullException';
import { attachActivitySource, attachActivityUser, attachActivityUsername, checkUser, saveActivity, saveActivityError } from './commonAuth';


const name = 'linkedin';
export function oauthLinkedinInit(linkedin: BaseOAuth, url: string) {
    //const linkedin = auth.oauth?.providers.find(x => x.type == 'linkedin')
    passport.use(new passportlinkedin.Strategy({
        clientID: linkedin?.clientId || '',
        clientSecret: linkedin?.clientSecret || '',
        callbackURL: `${url}/login/callback/oauth/linkedin`,
        passReqToCallback: true,
        scope: ['r_emailaddress', 'r_liteprofile'],
    },
        async (req: any, accessToken: any, refreshToken: any, profile: any, done: any) => {

            try {

                attachActivitySource(req, name);

                const email = profile.emails[0].value;
                attachActivityUsername(req, email);
                const uname = profile.displayName;
                logger.info(`passport linkedin with email: ${email}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                if (!linkedin.isEnabled)
                    throw new RestfullException(401, ErrorCodes.ErrDisabledSource, ErrorCodes.ErrDisabledSource, 'disabled source');
                const source = `${linkedin.baseType}-${linkedin.type}`;
                let user = await configService.getUserByUsername(email);
                if (!user) {
                    if (!linkedin.saveNewUser)
                        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrSaveNewUserDisabled, "new user save invalid");
                    let userSave: User = HelperService.createUser(source, email, uname, '');
                    userSave.isVerified = true;
                    await configService.saveUser(userSave);
                    //get back
                    user = await configService.getUserByUsername(email);
                    attachActivityUser(req, user);

                } else {
                    attachActivityUser(req, user);
                    await checkUser(user, linkedin);
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

export function oauthLinkedinUnuse() {
    passport.unuse(name);
}
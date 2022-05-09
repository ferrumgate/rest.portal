
import passport from 'passport';
import passportlocal from 'passport-local';
import passportlinkedin from 'passport-linkedin-oauth2';
import { AuthOption } from '../../model/authOption';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { User } from '../../model/user';
import { Util } from '../../util';

export function linkedinInit(authOption: AuthOption, url: string) {
    passport.use(new passportlinkedin.Strategy({
        clientID: authOption.linkedin?.clientID || '',
        clientSecret: authOption.linkedin?.clientSecret || '',
        callbackURL: `${url}/api/auth/linkedin/callback`,
        passReqToCallback: true,
        scope: ['r_emailaddress', 'r_liteprofile'],
    },
        async (req: any, accessToken: any, refreshToken: any, profile: any, done: any) => {
            try {
                const email = profile.emails[0];
                const name = profile.displayName;
                logger.info(`passport linkedin with email: ${email}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;

                let user = await configService.getUserByEmail(email);
                if (!user) {
                    let userSave: User = {
                        source: 'linkedin',
                        email: email,
                        id: Util.randomNumberString(16),
                        name: name,
                        isLocked: false,
                        isVerified: true,
                        groupIds: [],
                        password: Util.bcryptHash(Util.createRandomHash(64)),
                        is2FA: false,
                        insertDate: new Date().toISOString(),
                        updateDate: new Date().toISOString()
                    }
                    await configService.saveUser(userSave);

                }
                user = await configService.getUserByEmail(email);
                //set user to request object
                req.currentUser = user;
                return done(null, user);

            } catch (err) {
                return done(err);
            }
        }
    ));
}
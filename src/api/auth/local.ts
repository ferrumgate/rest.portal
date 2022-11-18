
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
import { RBACDefault } from '../../model/rbac';
import { attachActivitySource, attachActivityUser, attachActivityUsername, checkUser, saveActivity, saveActivityError } from './commonAuth';



const name = 'local';

export function localInit() {

    passport.use(new passportlocal.Strategy(
        { session: false, passReqToCallback: true },
        async (req: any, username: any, password: any, done: any) => {
            let tryUsername = username;
            try {

                attachActivitySource(req, name);
                logger.info(`passport local with username: ${username}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                if (!username || !password)
                    throw new RestfullException(400, ErrorCodes.ErrBadArgument, "bad argument");
                attachActivityUsername(req, username);
                let user = await configService.getUserByUsernameAndPass(username, password);
                if (!user)
                    throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'bad user');
                attachActivityUser(req, user);
                //get user roles if local is disabled
                const local = await configService.getAuthSettingsLocal();
                await checkUser(user, local);

                if (!local.isEnabled) {
                    const roles = await configService.getUserRoles(user);
                    const roleAdmin = roles.find(x => x.id == RBACDefault.roleAdmin.id)

                    if (!roleAdmin) {//not admin user,
                        throw new RestfullException(401, ErrorCodes.ErrDisabledSource, "disabled source");
                    }
                }
                //set user to request object
                req.currentUser = user;
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

export function localUnuse() {
    passport.unuse(name);
}
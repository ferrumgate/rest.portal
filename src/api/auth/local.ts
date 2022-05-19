
import passport from 'passport';
import passportlocal from 'passport-local';
import passportgoogle from 'passport-google-oauth2';
import { AuthOption } from '../../model/authOption';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { User } from '../../model/user';
import { Util } from '../../util';
import { ErrorCodes, RestfullException } from '../../restfullException';



export async function checkUser(user: User | undefined) {
    if (!user)
        throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'not found');
    if (!user.isVerified)
        throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'not found');
    if (user.isLocked)
        throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'not found');

}

export function localInit() {
    passport.use(new passportlocal.Strategy(
        { session: false, passReqToCallback: true },
        async (req: any, username: any, password: any, done: any) => {
            try {
                logger.info(`passport local with username: ${username}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                if (!username || !password)
                    throw new RestfullException(400, ErrorCodes.ErrBadArgument, "bad argument");
                const user = await configService.getUserByEmailAndPass(username, password);
                await checkUser(user);
                //set user to request object
                req.currentUser = user;
                return done(null, user);

            } catch (err) {
                return done(err);
            }

        }
    ));
}
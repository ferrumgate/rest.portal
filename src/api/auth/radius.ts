
import passport from 'passport';
import passportlocal from 'passport-local';
import passportgoogle from 'passport-google-oauth2';
import { AuthSettings, BaseRadius } from '../../model/authSettings';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { User } from '../../model/user';
import { Util } from '../../util';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../../restfullException';
import { HelperService } from '../../service/helperService';
import { RBACDefault } from '../../model/rbac';
import { attachActivitySource, attachActivityUser, attachActivityUsername, checkUser, makePassportName, saveActivity, saveActivityError } from './commonAuth';
const radius = require('radius');
const Client = require('node-radius-client');
const {
    dictionaries: {
        rfc2865: {
            file,
            attributes,
        },
    },
} = require('node-radius-utils');


const name = 'radius';
export function radiusInit(radius: BaseRadius) {
    const client = new Client({
        host: radius.host,
        dictionaries: [
            file,
        ],
    });

    passport.use(name, new passportlocal.Strategy(
        { session: false, passReqToCallback: true },
        async (req: any, username: any, password: any, done: any) => {
            let tryUsername = username;
            try {

                attachActivitySource(req, name);
                logger.info(`passport radius ${radius.name} with username: ${username}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                if (!username || !password)
                    throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrUsernameOrPasswordInvalid, "bad argument");
                attachActivityUsername(req, username);

                if (!radius.isEnabled)// check extra
                    throw new RestfullException(401, ErrorCodes.ErrDisabledSource, ErrorCodes.ErrDisabledSource, 'disabled source');


                await client.accessRequest({
                    secret: radius.secret,
                    attributes: [
                        [attributes.USER_NAME, username],
                        [attributes.USER_PASSWORD, password],
                    ],
                })

                const source = `${radius.baseType}-${radius.type}`;
                let user = await configService.getUserByUsername(username);
                if (!user) {
                    if (!radius.saveNewUser)
                        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrSaveNewUserDisabled, "new user save invalid");
                    let userSave: User = HelperService.createUser(source, username, username, '');
                    userSave.isVerified = true;
                    await configService.saveUser(userSave);
                    //get back
                    user = await configService.getUserByUsername(username);
                    attachActivityUser(req, user);

                } else {
                    attachActivityUser(req, user);
                    await checkUser(user, radius);
                }

                //set user to request object
                req.currentUser = user;
                await saveActivity(req, 'login try');
                return done(null, user);

            } catch (err) {
                //we need to show this error
                logger.error(err);
                await saveActivityError(req, 'login try', err);
                return done(null, null, err);
            }

        }
    ));
    return name;
}

export function radiusUnuse() {
    passport.unuse(name);
}
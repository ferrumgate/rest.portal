import * as openid from 'openid-client';
import passport from 'passport';
import { logger } from '../../common';
import { BaseOpenId } from '../../model/authSettings';
import { User } from '../../model/user';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../../restfullException';
import { AppService } from '../../service/appService';
import { HelperService } from '../../service/helperService';
import { attachActivitySource, attachActivityUser, attachActivityUsername, checkUser, saveActivity, saveActivityError } from './commonAuth';


export async function openIdInit(openId: BaseOpenId, url: string) {
    if (!openId.authName)
        throw new RestfullException(500, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "open id needs an auth name");
    const name = openId.authName;
    const issuer = await openid.Issuer.discover(openId.discoveryUrl);

    const client = new issuer.Client({
        client_id: openId.clientId,
        client_secret: openId.clientSecret,
        redirect_uris: [`${url}/login/callback/openid/${name}`],
        //redirect_uris: [`${url}/api/auth/openid/${name}/callback`],
    })

    passport.use(name, new openid.Strategy({
        client: client,
        passReqToCallback: true,
        params: {
            scope: 'openid profile email'
        }
    },
        async (req: any, profile: any, userinfo: any, done: any) => {

            try {
                attachActivitySource(req, openId.name);

                const username = userinfo.email;
                attachActivityUsername(req, username);
                const uname = userinfo.name;

                logger.info(`passport open id ${openId.name}  directory with username: ${username}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const inputService = appService.inputService;

                if (!openId.isEnabled)// check extra
                    throw new RestfullException(401, ErrorCodes.ErrDisabledSource, ErrorCodes.ErrDisabledSource, 'disabled source');

                await inputService.checkIfExists(username);

                const source = `${openId.baseType}-${openId.type}`;
                let user = await configService.getUserByUsername(username);
                if (!user) {
                    if (!openId.saveNewUser)
                        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrSaveNewUserDisabled, "new user save invalid");
                    let userSave: User = HelperService.createUser(source, username, uname, '');
                    userSave.isVerified = true;
                    await configService.saveUser(userSave);
                    //get back
                    user = await configService.getUserByUsername(username);
                    attachActivityUser(req, user);

                } else {
                    attachActivityUser(req, user);
                    await checkUser(user, openId);
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

export function openIdUnuse(name: string) {
    passport.unuse(name);
}
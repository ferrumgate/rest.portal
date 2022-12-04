
import passport from 'passport';

import * as samlAuth from 'passport-saml';
import { AuthOAuth, AuthSettings, BaseLdap, BaseOAuth, BaseSaml } from '../../model/authSettings';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { User } from '../../model/user';
import { Util } from '../../util';
import { HelperService } from '../../service/helperService';
import { group } from 'console';
import { ErrorCodes, RestfullException } from '../../restfullException';
import { attachActivitySource, attachActivityUser, attachActivityUsername, checkUser, saveActivity, saveActivityError } from './commonAuth';

function prepareCert(cert: string) {
    return cert.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\r\n', '').replace('\n', '').replace(' ', '');
}
const name = 'auth0'
export function samlAuth0Init(saml: BaseSaml, url: string) {
    //const google = auth.oauth?.providers.find(x => x.type == 'google')
    passport.use(name, new samlAuth.Strategy({
        path: `/api/auth/saml/auth0/callback`,
        entryPoint: saml.loginUrl,
        issuer: saml.issuer,
        cert: prepareCert(saml.cert),
        passReqToCallback: true,


    },
        async (req: any, profile: any, done: any) => {

            try {
                attachActivitySource(req, name);

                const username = profile.attributes[saml.usernameField];
                attachActivityUsername(req, username);
                const uname = profile.attributes[saml.nameField];

                logger.info(`passport active directory with username: ${username}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const inputService = appService.inputService;

                if (!saml.isEnabled)// check extra
                    throw new RestfullException(401, ErrorCodes.ErrDisabledSource, ErrorCodes.ErrDisabledSource, 'disabled source');

                await inputService.checkIfExists(username);

                const source = `${saml.baseType}-${saml.type}`;
                let user = await configService.getUserByUsername(username);
                if (!user) {
                    let userSave: User = HelperService.createUser(source, username, uname, '');
                    userSave.isVerified = true;
                    await configService.saveUser(userSave);
                    //get back
                    user = await configService.getUserByUsername(username);
                    attachActivityUser(req, user);

                } else {
                    attachActivityUser(req, user);
                    await checkUser(user, saml);
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

export function samlAuth0Unuse() {
    passport.unuse(name);
}
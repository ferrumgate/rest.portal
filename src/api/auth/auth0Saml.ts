
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
import { checkUser } from './commonAuth';


export function samlAuth0Init(saml: BaseSaml, url: string) {
    //const google = auth.oauth?.providers.find(x => x.type == 'google')
    passport.use('auth0', new samlAuth.Strategy({
        path: `/api/auth/saml/auth0/callback`,
        entryPoint: saml.loginUrl,
        issuer: saml.issuer,
        cert: saml.cert,// Buffer.from(saml.cert, 'base64').toString('utf-8'),
        passReqToCallback: true,


    },
        async (req: any, profile: any, done: any) => {
            try {

                const username = profile.attributes[saml.usernameField];
                const name = profile.attributes[saml.nameField];

                logger.info(`passport active directory with username: ${username}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const inputService = appService.inputService;

                if (!saml.isEnabled)// check extra
                    throw new RestfullException(401, ErrorCodes.ErrDisabledSource, 'disabled source');

                await inputService.checkIfExists(username);

                const source = `${saml.baseType}-${saml.type}`;
                let user = await configService.getUserByUsername(username);
                if (!user) {
                    let userSave: User = HelperService.createUser(source, username, name, '');
                    userSave.isVerified = true;
                    await configService.saveUser(userSave);
                    //get back
                    user = await configService.getUserByUsername(username);

                } else {
                    await checkUser(user, saml);
                }

                //set user to request object
                req.currentUser = user;
                return done(null, user);


            } catch (err) {
                return done(null, null, err);
            }
        }
    ));
    return 'auth0'
}
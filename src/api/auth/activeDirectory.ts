
import passport from 'passport';
import passportlocal from 'passport-local';
import * as ldapAuth from 'passport-ldapauth';
import { AuthOAuth, AuthSettings, BaseLdap, BaseOAuth } from '../../model/authSettings';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { User } from '../../model/user';
import { Util } from '../../util';
import { HelperService } from '../../service/helperService';
import { group } from 'console';
import { ErrorCodes, RestfullException } from '../../restfullException';
import { attachActivitySource, attachActivityUser, attachActivityUsername, checkUser, saveActivity, saveActivityError } from './commonAuth';
import { stringify } from 'querystring';
import { ActivityStatus } from '../../model/activityLog';


function findGroups(groups: string[]) {
    let items = [];
    for (const group of groups) {
        const tmp = group.split(',');
        if (tmp.length) {
            const gr = tmp[0].replace('cn=', '').replace('CN=', '');
            if (gr)
                items.push(gr);
        }
    }
    return items;
}

const name = 'activedirectory';

export function activeDirectoryInit(ldap: BaseLdap, url: string) {

    passport.use(name, new ldapAuth.default({

        server: {
            url: ldap.host,
            bindDN: ldap.bindDN,
            bindCredentials: ldap.bindPass,
            searchBase: ldap.searchBase,
            searchFilter: ldap.searchFilter || `(${ldap.usernameField}={{username}})`

        },
        passReqToCallback: true,
        usernameField: 'username',
        passwordField: 'password'

    },
        async (req: any, userAD: any, done: any) => {
            let tryUsername = '';//save tried username for errors
            try {

                attachActivitySource(req, name);
                const username = userAD[ldap.usernameField];
                attachActivityUsername(req, username);
                const groups = userAD[ldap.groupnameField];
                logger.info(`passport active directory with username: ${username}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const inputService = appService.inputService;
                const activityService = appService.activityService;

                if (!ldap.isEnabled)// check extra
                {
                    logger.error(`ldap is disabled`);
                    throw new RestfullException(401, ErrorCodes.ErrDisabledSource, ErrorCodes.ErrDisabledSource, 'disabled source');
                }

                await inputService.checkIfExists(username);
                await inputService.checkIfExists(groups);
                const groupList = findGroups(groups);

                //check group filtering
                if (ldap.allowedGroups?.length) {

                    let foundedGroups = ldap.allowedGroups.filter(y => groupList.find(z => z == y));
                    if (!foundedGroups.length) {
                        {
                            logger.error(`user group ${groupList.join(',')} not in ${ldap.allowedGroups.join(',')}`);
                            throw new RestfullException(401, ErrorCodes.ErrNotInLdapGroups, ErrorCodes.ErrNotInLdapGroups, "user invalid");
                        }
                    }
                }

                const source = `${ldap.baseType}-${ldap.type}`;
                let user = await configService.getUserByUsername(username);
                if (!user) {
                    let userSave: User = HelperService.createUser(source, username, username, '');
                    userSave.isVerified = true;
                    await configService.saveUser(userSave);
                    //get back
                    user = await configService.getUserByUsername(username);
                    attachActivityUser(req, user);

                } else {
                    attachActivityUser(req, user);
                    await checkUser(user, ldap);
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

export function activeDirectoryUnuse() {
    passport.unuse(name);
}
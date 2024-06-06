import passport from 'passport';
import * as ldapAuth from 'passport-ldapauth';
import { logger } from '../../common';
import { BaseLdap } from '../../model/authSettings';
import { User } from '../../model/user';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../../restfullException';
import { AppService } from '../../service/appService';
import { HelperService } from '../../service/helperService';
import { LogicService } from '../../service/logicService';
import { Util } from '../../util';
import { attachActivitySource, attachActivityUser, attachActivityUsername, checkUser, saveActivity, saveActivityError } from './commonAuth';

function findGroups(groups: string[] | string | undefined) {

    let items: string[] = [];
    if (!groups) return items;
    let groupsArray = [];
    if (Array.isArray(groups))
        groupsArray = groups;
    else
        if (typeof (groups) != 'string') {
            return items;
        } else
            groupsArray.push(groups);
    for (const group of groupsArray) {
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
            searchFilter: ldap.searchFilter || `(${ldap.usernameField}={{username}})`,
            tlsOptions: ldap.tlsCaRoot ?
                {
                    ca: Util.splitCertFile(ldap.tlsCaRoot).map(x => Buffer.from(x)),
                    rejectUnauthorized: ldap.tlsValidateCert
                } : undefined,

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
                const auditService = appService.auditService;

                if (!ldap.isEnabled)// check extra
                {
                    logger.error(`ldap is disabled`);
                    throw new RestfullException(401, ErrorCodes.ErrDisabledSource, ErrorCodes.ErrDisabledSource, 'disabled source');
                }

                await inputService.checkIfExists(username);
                await inputService.checkIfExists(groups);
                const adGroupList = findGroups(groups);

                //check group filtering
                if (ldap.allowedGroups?.length) {

                    let foundedGroups = ldap.allowedGroups.filter(y => adGroupList.find(z => z == y));
                    if (!foundedGroups.length) {
                        {
                            logger.error(`user group ${adGroupList.join(',')} not in ${ldap.allowedGroups.join(',')}`);
                            throw new RestfullException(401, ErrorCodes.ErrNotInLdapGroups, ErrorCodes.ErrNotInLdapGroups, "user invalid");
                        }
                    }
                }

                const source = `${ldap.baseType}-${ldap.type}`;
                let user = await configService.getUserByUsername(username);
                if (!user) {
                    if (!ldap.saveNewUser)
                        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrSaveNewUserDisabled, "new user save invalid");
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
                //check user group

                if (ldap.syncGroups) {
                    let allOurGroups = await configService.getGroupsAll();
                    adGroupList.forEach(async (adGroupName) => {
                        var ourGroup = allOurGroups.find(x => x.name.toLowerCase() == adGroupName.toLowerCase());
                        //save new group
                        if (!ourGroup) {
                            ourGroup = {
                                id: Util.randomNumberString(16),
                                insertDate: new Date().toISOString(),
                                updateDate: new Date().toISOString(),
                                isEnabled: true,
                                labels: [],
                                name: adGroupName,
                                source: "ldap"
                            }
                            await configService.saveGroup(ourGroup);
                        }
                        if (user) {
                            var userHasGroup = user.groupIds.find(x => x == ourGroup?.id);
                            if (!userHasGroup && ourGroup) {
                                if (!user.groupIds)
                                    user.groupIds = [];
                                user.groupIds.push(ourGroup.id);
                            }

                        }
                    });

                    //check user groups
                    if (user) {
                        var removeGroupIds: string[] = [];
                        user.groupIds.forEach((groupId) => {
                            var ourGroup = allOurGroups.find(x => x.id == groupId && x.source == 'ldap');
                            if (ourGroup) {
                                var adGroupName = adGroupList.find(y => y.toLowerCase() == ourGroup?.name.toLowerCase());
                                if (!adGroupName) {
                                    removeGroupIds.push(groupId);
                                }
                            }

                        });
                        user.groupIds = user.groupIds.filter(x => !removeGroupIds.includes(x));
                    }
                    if (user) {
                        const { isChanged, userDb } = await LogicService.checkUserToUpdate(user.id, user, configService);
                        const { before, after } = await configService.saveUser(userDb);
                        //no audit, auto process
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

export function activeDirectoryUnuse() {
    passport.unuse(name);
}
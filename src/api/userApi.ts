import express from "express";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import passport from "passport";
import { RBACDefault } from "../model/rbac";
import { config } from "process";
import { authorizeAsAdmin } from "./commonApi";
import { AuthSession } from "../model/authSession";
import { UserNetworkListResponse } from "../service/policyService";




/////////////////////////////////  confirm //////////////////////////////////
export const routerUserEmailConfirm = express.Router();
//user/confirm
routerUserEmailConfirm.post('/', asyncHandler(async (req: any, res: any, next: any) => {
    const key = req.query.key || req.body.key;
    if (!key)
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "needs key argument");

    logger.info(`user confirm with key: ${key}`);
    const appService = req.appService as AppService;
    const configService = appService.configService;
    const redisService = appService.redisService;

    const isSystemConfigured = await configService.getIsConfigured();
    if (!isSystemConfigured) {
        logger.warn(`system is not configured yet`);
        throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
    }

    //check key from redis
    const rkey = `/user/confirm/${key}`;
    const userId = await redisService.get(rkey, false) as string;
    if (!userId) {
        logger.fatal(`user confirm key not found key: ${key}`);
        throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrKeyNotFound, "not found key");
    }
    const userDb = await configService.getUserById(userId);
    if (!userDb) {//check for safety
        logger.warn(`user confirm user id not found ${userId}`);
        throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrUserNotFound, "argument problem");
    }
    //verify
    userDb.isVerified = true;
    await configService.saveUser(userDb);
    //delete the key for security
    await redisService.delete(rkey);

    logger.info(`user confirm is ok ${key}`);
    return res.status(200).json({ result: true });

}))

/////////////////////////////////// forgotpass //////////////////////////
export const routerUserForgotPassword = express.Router();

//user/forgotpass
routerUserForgotPassword.post('/', asyncHandler(async (req: any, res: any, next: any) => {
    const email = req.body.username || req.query.username;
    if (!email) {
        logger.error(`forgot password email parameter absent`);
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "needs username parameter");
    }

    const appService = req.appService as AppService;
    const configService = appService.configService;
    const redisService = appService.redisService;
    const inputService = appService.inputService;
    const templateService = appService.templateService;
    const emailService = appService.emailService;

    const isSystemConfigured = await configService.getIsConfigured();
    if (!isSystemConfigured) {
        logger.warn(`system is not configured yet`);
        throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
    }
    const authSettings = await configService.getAuthSettings();
    if (!authSettings.local.isForgotPassword) {
        logger.warn(`forgotpassword is not allowed`);
        throw new RestfullException(405, ErrorCodes.ErrMethodNotAllowed, ErrorCodes.ErrMethodNotAllowed, "forgotpassword not enabled");
    }

    logger.info(`forgot password with email ${email}`);
    //this is security check if input is not valid email then throw exception
    await inputService.checkEmail(email);

    const userDb = await configService.getUserByUsername(email);
    if (!userDb) {

        logger.error(`forgot password no user found with email ${email}`);
        return res.status(200).json({ result: true });
    }
    /* if (userDb.source != 'local') {
        //security check only local users can forgot password
        logger.error(`forgot password user is not local with email ${email}`);
        return res.status(200).json({ result: true });
    } */
    const key = Util.createRandomHash(48);
    const link = `${req.baseHost}/user/resetpass?key=${key}`
    await redisService.set(`/user/resetpass/${key}`, userDb.id, { ttl: 7 * 24 * 60 * 60 * 1000 })//1 days

    const logoPath = (await configService.getLogo()).defaultPath || 'logo.png';
    const logo = `${req.baseHost}/dassets/img/${logoPath}`;
    const html = await templateService.createForgotPassword(userDb.name, link, logo);
    //fs.writeFileSync('/tmp/abc.html', html);
    logger.info(`forgot password sending reset link to ${userDb.username}`);
    //send reset link over email
    await emailService.send({ to: userDb.username, subject: 'Reset your password', html: html });
    return res.status(200).json({ result: true });

}))

/////////////////////////////// reset password ////////////////////////////

export const routerUserResetPassword = express.Router();


routerUserResetPassword.post('/', asyncHandler(async (req: any, res: any, next: any) => {

    const pass = req.body.pass;
    const key = req.body.key;
    if (!pass || !key) {
        logger.error(`reset password pass parameter absent or key absent`);
        throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "needs pass parameter");
    }



    const rkey = `/user/resetpass/${key}`;
    logger.info(`reset password with key: ${key} `)
    const appService = req.appService as AppService;
    const configService = appService.configService;
    const redisService = appService.redisService;
    const inputService = appService.inputService;
    const templateService = appService.templateService;
    const emailService = appService.emailService;

    const isSystemConfigured = await configService.getIsConfigured();
    if (!isSystemConfigured) {
        logger.warn(`system is not configured yet`);
        throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
    }

    inputService.checkPasswordPolicy(pass);

    const userId = await redisService.get(rkey, false) as string;
    if (!userId) {
        logger.fatal(`reset password key not found with id: ${key}`);
        throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrKeyNotFound, "not authorized");
    }
    const user = await configService.getUserById(userId);
    if (!user) {
        logger.fatal(`reset password user not found with userId: ${userId}`);
        throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrUserNotFound, "not authorized");
    }
    inputService.checkEmail(user.username);//username must be email, security barrier

    user.password = Util.bcryptHash(pass);
    await configService.saveUser(user);
    logger.info(`reset password pass changed for ${user.username}`);
    await redisService.delete(rkey);
    return res.status(200).json({ result: true });

}))


//////////////////////////////// authenticated user /////////////////////
/////////////////////////////// current user ////////////////////////////

export const routerUserAuthenticated = express.Router();


//// get current user networks

routerUserAuthenticated.get('/current/network',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(async (req: any, res: any, next: any) => {


        logger.info(`getting current user networks`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const policyService = appService.policyService;
        const sessionService = appService.sessionService;
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;


        const networks = await policyService.userNetworks(currentUser, currentSession?.is2FA, currentSession?.ip);
        const results = networks.map(x => {
            return {
                id: x.network.id, name: x.network.name,
                action: x.action, needs2FA: x.needs2FA, needsIp: x.needsIp,
                sshHost: x.network.sshHost,
            }
        })

        return res.status(200).json({ items: results });

    }))




routerUserAuthenticated.get('/current',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(async (req: any, res: any, next: any) => {
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const user = req.currentUser as User;

        const roles = await configService.getUserRoles(user);
        //send min data for security
        return res.status(200).json(
            {
                id: user.id,
                name: user.name,
                username: user.username,
                is2FA: user.is2FA,
                roles: roles
            });
    })
);






routerUserAuthenticated.get('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting user with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const user = await configService.getUserById(id);
        if (!user) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrUserNotFound, 'no user');

        return res.status(200).json(user);

    }))


interface UserSearch {

    search: string,
    isVerified?: boolean,
    isLocked?: boolean,
    isEmailVerified?: boolean,
    is2FA?: boolean,
    groupIds: string[],
    roleIds: string[],
    ids: string[],
    page: number;
    pageSize: number;
    isApiKey?: boolean;
    format: string

}

function convertToUserOptionToBoolean(val?: string): boolean | undefined {
    if (!val) return undefined;
    if (val == 'none') return undefined;
    if (val == 'yes' || val == 'true') return true;
    return false;
}



routerUserAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search: UserSearch = {
            search: req.query.search || '',
            isVerified: convertToUserOptionToBoolean(req.query.isVerified),
            isLocked: convertToUserOptionToBoolean(req.query.isLocked),
            isEmailVerified: convertToUserOptionToBoolean(req.query.isEmailVerified),
            is2FA: convertToUserOptionToBoolean(req.query.is2FA),
            groupIds: Util.convertToArray(req.query.groupIds),
            roleIds: Util.convertToArray(req.query.roleIds),
            ids: Util.convertToArray(req.query.ids),
            page: Util.convertToNumber(req.query.page),
            pageSize: Util.convertToNumber(req.query.pageSize),
            format: req.query.simple
        }

        logger.info(`getting users`);
        const appService = req.appService as AppService;
        const configService = appService.configService;


        const items = await configService.getUsersBy(search.page, search.pageSize, search.search,
            search.ids, search.groupIds, search.roleIds,
            search.is2FA, search.isVerified, search.isLocked,
            search.isEmailVerified, false);

        if (search.format == 'simple')
            items.items = items.items.map(x => {
                return {
                    id: x.id, name: x.name, username: x.username, email: x.email
                } as any
            })

        return res.status(200).json({ items: items.items, total: items.total });

    }))

routerUserAuthenticated.delete('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete group with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const user = await configService.getUserById(id);
        if (!user) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrUserNotFound, 'no user');
        //check if any other admin user exists
        const adminUsers = await configService.getUserByRoleIds([RBACDefault.roleAdmin.id]);
        if (adminUsers.length == 1)
            throw new RestfullException(400, ErrorCodes.ErrNoAdminUserLeft, ErrorCodes.ErrNoAdminUserLeft, 'no admin user left');
        const { before } = await configService.deleteUser(user.id);
        await auditService.logDeleteUser(currentSession, currentUser, before);

        return res.status(200).json({});

    }))





routerUserAuthenticated.put('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as User;
        logger.info(`changing user settings for ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;


        await inputService.checkNotEmpty(input.id);
        const userDb = await configService.getUser(input.id);
        if (!userDb) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrUserNotFound, 'no user');

        //await inputService.checkNotEmpty(input.name);
        //only set name. isLocked, is2FA, roleIds, groupIds
        let isChanged = false;
        if (!Util.isUndefinedOrNull(input.name) && userDb.name != input.name) {
            isChanged = true;
            userDb.name = input.name;
        }
        if (input.labels) {
            if (!Util.isArrayEqual(input.labels, userDb.labels))
                isChanged = true;
            userDb.labels = input.labels;
        }
        if (!Util.isUndefinedOrNull(input.is2FA)) {

            if (!input.is2FA) {//only user can set false
                if (input.is2FA != userDb.is2FA)
                    isChanged = true;
                userDb.is2FA = input.is2FA;
            }
        }
        if (!Util.isUndefinedOrNull(input.isLocked)) {
            if (input.isLocked != userDb.isLocked)
                isChanged = true;
            userDb.isLocked = input.isLocked;
        }
        if (input.roleIds) {
            //security, check input roles are system defined roles
            const filterRoles = input.roleIds.filter(x => RBACDefault.systemRoleIds.includes(x))
            if (!Util.isArrayEqual(userDb.roleIds, filterRoles))
                isChanged = true;
            userDb.roleIds = filterRoles;
        }
        const groups = await configService.getGroupsAll();
        if (input.groupIds) {
            const filteredGroups = input.groupIds.filter(x => groups.find(y => y.id == x));
            if (!Util.isArrayEqual(filteredGroups, userDb.groupIds))
                isChanged = true;
            userDb.groupIds = filteredGroups;
        }

        //check if any other admin user exists
        const adminUsers = await configService.getUserByRoleIds([RBACDefault.roleAdmin.id]);
        if (adminUsers.length == 1 && adminUsers[0].id == userDb.id && !userDb.roleIds?.includes(RBACDefault.roleAdmin.id))
            throw new RestfullException(400, ErrorCodes.ErrNoAdminUserLeft, ErrorCodes.ErrNoAdminUserLeft, 'no admin user left');

        if (isChanged) {
            const { before, after } = await configService.saveUser(userDb);
            await auditService.logSaveUser(currentSession, currentUser, before, after);
        }

        return res.status(200).json(userDb);

    }))








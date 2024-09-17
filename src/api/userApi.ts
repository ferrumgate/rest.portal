import express, { query } from "express";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AuthSession } from "../model/authSession";
import { SSLCertificate, SSLCertificateBase } from "../model/cert";
import { ClientDevicePosture, DeviceLog } from "../model/device";
import { RBACDefault } from "../model/rbac";
import { User } from "../model/user";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { AppService } from "../service/appService";
import { ConfigService } from "../service/configService";
import { HelperService } from "../service/helperService";
import { LogicService } from "../service/logicService";
import { Util } from "../util";
import { UtilPKI } from "../utilPKI";
import { attachActivity, attachActivitySession, attachActivityUser, attachActivityUsername, saveActivity, saveActivityError } from "./auth/commonAuth";
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import { authorizeAsAdmin, authorizeAsAdminOrDevOps } from "./commonApi";
import { AuditService } from "../service/auditService";




/////////////////////////////////  confirm //////////////////////////////////
export const routerUserEmailConfirm = express.Router();
//user/confirm
routerUserEmailConfirm.post('/', asyncHandler(async (req: any, res: any, next: any) => {
    try {
        attachActivity(req);
        const key = req.query.key || req.body.key;
        if (!key)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "needs key argument");

        logger.info(`user confirm with key: ${key}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const redisService = appService.redisService;
        const sessionService = appService.sessionService;
        const activityService = appService.activityService;
        const auditService = appService.auditService;


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

        //audit log and activity logs needs
        req.currentSession = await sessionService.createFakeSession(userDb, false, req.clientIp, userDb.source);
        attachActivitySession(req, req.currentSession);
        attachActivityUser(req, userDb);


        await configService.saveUser(userDb);
        //delete the key for security
        await redisService.delete(rkey);


        logger.info(`user confirm is ok ${key}`);
        await auditService.logUserConfirm(req.currentSession, userDb);
        await saveActivity(req, 'user confirm');

        return res.status(200).json({ result: true });
    } catch (err) {
        saveActivityError(req, 'user confirm', err);
        throw err;
    }

}))

/////////////////////////////////// forgotpass //////////////////////////
export const routerUserForgotPassword = express.Router();

//user/forgotpass
routerUserForgotPassword.post('/', asyncHandler(async (req: any, res: any, next: any) => {
    try {
        attachActivity(req);

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
        const auditService = appService.auditService;
        const sessionService = appService.sessionService;





        const isSystemConfigured = await configService.getIsConfigured();
        if (!isSystemConfigured) {
            logger.warn(`system is not configured yet`);
            throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
        }
        const local = await configService.getAuthSettingLocal();
        if (!local.isForgotPassword) {
            logger.warn(`forgotpassword is not allowed`);
            throw new RestfullException(405, ErrorCodes.ErrMethodNotAllowed, ErrorCodes.ErrMethodNotAllowed, "forgotpassword not enabled");
        }

        logger.info(`forgot password with email ${email}`);
        //this is security check if input is not valid email then throw exception
        await inputService.checkEmail(email);

        const userDb = await configService.getUserByUsername(email);
        if (!userDb) {

            logger.error(`forgot password no user found with email ${email}`);
            attachActivityUsername(req, email);
            await saveActivity(req, 'forgot password');
            return res.status(200).json({ result: true });
        }

        //audit log and activity logs needs
        req.currentSession = await sessionService.createFakeSession(userDb, false, req.clientIp, userDb.source);
        attachActivitySession(req, req.currentSession);
        attachActivityUser(req, userDb);
        /* if (userDb.source != 'local') {
            //security check only local users can forgot password
            logger.error(`forgot password user is not local with email ${email}`);
            return res.status(200).json({ result: true });
        } */
        const key = Util.createRandomHash(48);
        const link = `${req.baseHost}/user/resetpass?key=${key}`
        await redisService.set(`/user/resetpass/${key}`, userDb.id, { ttl: 7 * 24 * 60 * 60 * 1000 })//7 days

        const logoPath = (await configService.getLogo()).defaultPath || 'logo.png';
        const logo = `${req.baseHost}/dassets/img/${logoPath}`;
        const html = await templateService.createForgotPassword(userDb.name, link, logo);
        //fs.writeFileSync('/tmp/abc.html', html);
        logger.info(`forgot password sending reset link to ${userDb.username}`);
        //send reset link over email
        await emailService.send({ to: userDb.username, subject: 'Reset your password', html: html });


        await auditService.logForgotPassword(req.currentSession, userDb, email);
        await saveActivity(req, 'forgot password');

        return res.status(200).json({ result: true });
    } catch (err) {
        saveActivityError(req, 'forgot password', err);
        throw err;
    }

}))

/////////////////////////////// reset password ////////////////////////////

export const routerUserResetPassword = express.Router();


routerUserResetPassword.post('/', asyncHandler(async (req: any, res: any, next: any) => {
    try {
        attachActivity(req);

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
        const auditService = appService.auditService;
        const sessionService = appService.sessionService;

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
        //audit
        req.currentSession = await sessionService.createFakeSession(user, false, req.clientIp, user.source);
        attachActivitySession(req, req.currentSession);
        attachActivityUser(req, user);

        inputService.checkEmail(user.username);//username must be email, security barrier

        user.password = Util.bcryptHash(pass);
        await configService.saveUser(user);

        await redisService.delete(rkey);
        logger.info(`reset password pass changed for ${user.username}`);

        await auditService.logResetPassword(req.currentSession, user);
        await saveActivity(req, 'reset password');

        return res.status(200).json({ result: true });
    } catch (err) {
        saveActivityError(req, 'reset password', err);
        throw err;
    }

}))






//////////////////////////////// authenticated user /////////////////////
/////////////////////////////// current user ////////////////////////////

export const routerUserAuthenticated = express.Router();

//// get current user dynamic device posture

routerUserAuthenticated.get('/current/device/posture/parameters',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(async (req: any, res: any, next: any) => {


        logger.info(`getting current user device posture parameters`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const policyService = appService.policyService;
        const sessionService = appService.sessionService;
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;


        const results = await policyService.userDevicePostureParameters(currentUser, currentSession, currentSession?.ip);

        return res.status(200).json({ items: results });

    }))

//// save current user connected device posture

routerUserAuthenticated.post('/current/device/posture',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`save current user device posture`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const policyService = appService.policyService;
        const sessionService = appService.sessionService;
        const inputService = appService.inputService;
        const deviceService = appService.deviceService;

        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const clientDevicePosture = req.body as ClientDevicePosture;

        await inputService.checkNotEmpty(clientDevicePosture.clientId)
        await inputService.checkStringLength(clientDevicePosture.clientId, 16);
        await deviceService.saveDevicePosture(clientDevicePosture);
        //const devicelog = await deviceService.convertDevicePostureToDeviceLog(clientDevicePosture, currentUser.id, currentUser.username);
        //await deviceService.save(devicelog);
        await sessionService.setSession(currentSession.id, {
            deviceId: clientDevicePosture.clientId,
            deviceName: clientDevicePosture.hostname,
            osName: clientDevicePosture.os.name,
            osVersion: clientDevicePosture.os.version,
            osPlatform: clientDevicePosture.platform
        })
        return res.status(200).json({});

    }))


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
        const deviceService = appService.deviceService;


        const session = req.currentSession as AuthSession;
        //device log 
        let deviceLog: DeviceLog | null = null;
        let devicePosture = await deviceService.getDevicePosture(session.deviceId || '');
        if (devicePosture)
            deviceLog = await deviceService.convertDevicePostureToDeviceLog(devicePosture, currentUser, undefined);

        const networks = await policyService.userNetworks(currentUser, currentSession, currentSession?.ip, devicePosture);
        const results = networks.map(x => {
            return {
                id: x.network.id, name: x.network.name,
                action: x.action,
                needs2FA: x.needs2FA,
                needsIp: x.needsIp,
                needsDevicePosture: x.needsDevicePosture,
                needsTime: x.needsTime,
                sshHost: x.network.sshHost,
            }
        })
        //save device log
        if (deviceLog) {
            for (const result of networks) {
                deviceLog.networkdId = result.network.id;
                deviceLog.networkName = result.network.name;
                deviceLog.isHealthy = result.whyNeedsDevicePosture ? false : true;
                deviceLog.whyNotHealthy = result.whyNeedsDevicePosture;
                await deviceService.save(deviceLog);
            }
        }

        return res.status(200).json({ items: results });

    }))


/// current user new qr code

routerUserAuthenticated.get('/current/2fa/rekey',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt']),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting current user 2fa`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const policyService = appService.policyService;
        const sessionService = appService.sessionService;
        const redisService = appService.redisService;
        const t2FAService = appService.twoFAService;
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const user = await configService.getUserById(currentUser.id);
        HelperService.isValidUser(user);
        const key = t2FAService.generateSecret();
        const rkey = Util.randomNumberString(16);
        await redisService.set(`/2fa/id/${rkey}`, key, { ttl: 30 * 60 * 1000 });


        return res.status(200).json({ key: rkey, t2FAKey: key });

    }))

// get current user 2fa settings
routerUserAuthenticated.get('/current/2fa',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt']),
    asyncHandler(async (req: any, res: any, next: any) => {
        const refresh = req.query.refresh;
        logger.info(`getting current user 2fa`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const policyService = appService.policyService;
        const sessionService = appService.sessionService;
        const t2FAService = appService.twoFAService;
        const currentUser = req.currentUser as User;
        const redisService = appService.redisService;
        const currentSession = req.currentSession as AuthSession;

        const user = await configService.getUserById(currentUser.id);
        HelperService.isValidUser(user);
        if (!user)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrUserNotFound, 'not found');
        const sensitiveData = await configService.getUserSensitiveData(user.id);
        let secret = sensitiveData.twoFASecret || t2FAService.generateSecret();

        const rkey = Util.randomNumberString(16);
        await redisService.set(`/2fa/id/${rkey}`, secret, { ttl: 30 * 60 * 1000 });


        return res.status(200).json({ is2FA: user?.is2FA, key: rkey, t2FAKey: secret });

    }))
/// set current user 2fa settings

routerUserAuthenticated.put('/current/2fa',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt']),
    asyncHandler(async (req: any, res: any, next: any) => {
        const request = req.body as { is2FA: boolean, key?: string, token?: string }
        logger.info(`saving current user 2fa settings`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const policyService = appService.policyService;
        const sessionService = appService.sessionService;
        const redisService = appService.redisService;
        const t2FAService = appService.twoFAService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const currentUser = req.currentUser as User;

        const currentSession = req.currentSession as AuthSession;
        await inputService.checkNotNullOrUndefined(request.is2FA);
        const user = await configService.getUserById(currentUser.id);
        HelperService.isValidUser(user);
        if (!user)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrUserNotFound, 'not found');
        const userSensitiveData = await configService.getUserSensitiveData(currentUser.id);

        let isChanged = false;
        if (!request.is2FA) {
            if (user.is2FA != request.is2FA) {
                user.is2FA = request.is2FA;
                user.twoFASecret = t2FAService.generateSecret();//change it for security
                isChanged = true;
            }
        } else {
            await inputService.checkNotEmpty(request.key);
            await inputService.checkNotEmpty(request.token);
            const secret = await redisService.get(`/2fa/id/${request.key}`, false) as string;
            await inputService.checkNotEmpty(secret);
            t2FAService.verifyToken(secret, request.token || '');
            if (userSensitiveData.twoFASecret != secret || !user.is2FA) {
                user.is2FA = true;
                user.twoFASecret = secret;
                isChanged = true;
            }



        }
        if (isChanged) {
            const { before, after } = await configService.saveUser(user);
            //we try to show a little data
            if (before)
                Util.any(before).twoFASecret2 = before.twoFASecret?.substring(0, 5);
            if (after)
                Util.any(after).twoFASecret2 = after.twoFASecret?.substring(0, 5);
            await auditService.logSaveUser(currentSession, currentUser, before, after);
        }

        return res.status(200).json({});

    }))


/// set current user password

routerUserAuthenticated.put('/current/pass',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt']),
    asyncHandler(async (req: any, res: any, next: any) => {
        const request = req.body as { oldPass: string, newPass: string }
        logger.info(`saving current user password settings`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const policyService = appService.policyService;
        const sessionService = appService.sessionService;
        const redisService = appService.redisService;
        const t2FAService = appService.twoFAService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const currentUser = req.currentUser as User;

        const currentSession = req.currentSession as AuthSession;
        await inputService.checkNotEmpty(request.oldPass);
        await inputService.checkPasswordPolicy(request.newPass);

        const user = await configService.getUserByIdAndPass(currentUser.id, request.oldPass);
        if (!user)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrUserNotFound, 'not found');
        if (!user.source.startsWith('local'))
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrOnlyAuthLocalIsValid, 'only local users');
        HelperService.isValidUser(user);

        let isChanged = false;
        if (request.oldPass != request.newPass) {
            isChanged = true;
            user.password = Util.bcryptHash(request.newPass);
            await configService.saveUser(user);

        }

        if (isChanged) {
            const { before, after } = await configService.saveUser(user);
            //we try to show a little data
            if (before)
                Util.any(before).password2 = 'before';
            if (after)
                Util.any(after).password2 = 'after';
            await auditService.logSaveUser(currentSession, currentUser, before, after);
        }

        return res.status(200).json({});

    }))


routerUserAuthenticated.get('/current/sensitiveData',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(async (req: any, res: any, next: any) => {
        const user = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        logger.info(`getting user sensitive data`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        let retData = await getSensitiveData(configService, user.id, true, true);
        if (!retData.cert?.publicCrt || !retData.apiKey?.key) {
            let data: InputChangeApiKeyAndCert = {
                apiKey: { key: retData.apiKey?.key || '' },
                cert: { publicCrt: retData.cert?.publicCrt, privateKey: retData.cert?.privateKey } as any
            };

            await changeApiKeyandCert(user, configService, user.id, data, auditService, currentSession);

        }
        retData = await getSensitiveData(configService, user.id, true, true);
        return res.status(200).json({ cert: retData.cert, apiKey: retData.apiKey });

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
                roles: roles,
                source: user.source
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
    loginMethods: string[],
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
            loginMethods: Util.convertToArray(req.query.loginMethods),
            ids: Util.convertToArray(req.query.ids),
            page: Util.convertToNumber(req.query.page),
            pageSize: Util.convertToNumber(req.query.pageSize),
            format: req.query.simple
        }

        logger.info(`getting users`);
        const appService = req.appService as AppService;
        const configService = appService.configService;


        const items = await configService.getUsersBy(search.page, search.pageSize, search.search,
            search.ids, search.groupIds, search.roleIds, search.loginMethods,
            search.is2FA, search.isVerified, search.isLocked,
            search.isEmailVerified);

        if (search.format == 'simple')
            items.items = items.items.map(x => {
                return {
                    id: x.id, name: x.name, username: x.username, email: x.email
                } as any
            })

        /*  if (process.env.LIMITED_MODE == 'true') {//limited mode only current user
             const user = req.currentUser as User;
             items.items = items.items.filter(x => x.id == user.id);
             items.total = items.items.length;
         } */

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

        logger.info(`delete user with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const user = await configService.getUserById(id);
        if (!user) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrUserNotFound, 'no user');
        const userRole = await configService.getUserRoles(user);
        if (userRole.find(x => x.id == RBACDefault.roleAdmin.id)) {
            //check if any other admin user exists
            const adminUsers = await configService.getUserByRoleIds([RBACDefault.roleAdmin.id]);
            if (adminUsers.length == 1)
                throw new RestfullException(400, ErrorCodes.ErrNoAdminUserLeft, ErrorCodes.ErrNoAdminUserLeft, 'no admin user left');
        }
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
        const { isChanged, userDb } = await LogicService.checkUserToUpdate(input.id, input, configService);

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


//becarefull, this methods resets a user password
//must be admin
routerUserAuthenticated.put('/pass',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as { id: string, pass: string };
        logger.info(`changing user settings for ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const isSystemConfigured = await configService.getIsConfigured();
        if (!isSystemConfigured) {
            logger.warn(`system is not configured yet`);
            throw new RestfullException(417, ErrorCodes.ErrNotConfigured, ErrorCodes.ErrNotConfigured, "not configured yet");
        }
        // user must be logged in with 2FA
        if (!currentSession.is2FA) {
            throw new RestfullException(400, ErrorCodes.Err2FANeeds, ErrorCodes.Err2FANeeds, "needs a 2FA login");
        }

        inputService.checkNotEmpty(input.id);
        inputService.checkPasswordPolicy(input.pass);
        const userDb = await configService.getUserById(input.id);
        if (!userDb) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrUserNotFound, 'no user');

        /*  if (process.env.LIMITED_MODE == 'true') {//limited mode only current user update itself
             const user = req.currentUser as User;
             if (user.id != userDb.id) {
                 throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrUserNotFound, 'no user');
             }
         } */

        userDb.password = Util.bcryptHash(input.pass);
        await configService.saveUser(userDb);

        logger.info(`user password hard reset for ${userDb.username}`);

        await auditService.logResetPasswordForOtherUser(req.currentSession, currentUser, userDb);


        return res.status(200).json({ result: true });

    }))

// becarefull, this method creates a user,
// username and password will automatic created
// just name, groupid, are input
routerUserAuthenticated.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdminOrDevOps),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as User;
        const createApiKey = req.query.apiKey == 'true';
        const createCert = req.query.cert == 'true';
        logger.info(`saving new apikey or cert based user`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const emailService = appService.emailService;
        const redisService = appService.redisService;
        const templateService = appService.templateService;



        const groupsIds = (await configService.getGroupsAll()).map(y => y.id);
        const userNameSurname = input.name || input.username || Util.randomNumberString(64);
        const username = input.username || Util.randomNumberString(64);

        const dbUser = await configService.getUserByUsername(username);
        if (dbUser) {
            throw new RestfullException(400, ErrorCodes.ErrAllreadyExits, ErrorCodes.ErrAllreadyExits, "user exists");
        }


        const userNew: User = HelperService.createUser('local-local', username, userNameSurname);
        userNew.isVerified = true;
        userNew.groupIds = input.groupIds.filter(x => groupsIds.includes(x));
        userNew.roleIds = [RBACDefault.roleUser.id];//no one can create admin just user


        if (createApiKey) {
            userNew.apiKey = { key: `${userNew.id}${Util.randomNumberString(64)}` };
        }

        if (createCert) {
            let parentCertId = input.cert?.parentId || '';
            if (!parentCertId) {
                const findedCert = (await configService.getInSSLCertificateAll()).find(x => x.category == 'auth' && x.isEnabled)
                if (findedCert)
                    parentCertId = findedCert.id;
            }
            const inCert = await configService.getInSSLCertificateSensitive(parentCertId);
            if (!inCert || !inCert.isEnabled)
                throw new RestfullException(400, ErrorCodes.ErrCertificateIsNotValid, ErrorCodes.ErrCertificateIsNotValid, "cert not found or is not enabled");
            const { publicCrt, privateKey } = await UtilPKI.createCertSigned(userNew.id, 'ferrumgate', 3650, false, [], inCert.publicCrt, inCert.privateKey);
            userNew.cert = {
                parentId: parentCertId,
                publicCrt: publicCrt,
                privateKey: privateKey
            }

        }

        const { before, after } = await configService.saveUser(userNew);
        await auditService.logSaveUser(currentSession, currentUser, before, after);
        const userDb = await configService.getUserById(userNew.id);
        const retData = await getSensitiveData(configService, userDb?.id || '', createApiKey, createCert);

        return res.status(200).json({ user: userDb, sensitiveData: retData });

    }))



routerUserAuthenticated.post('/invite',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { emails } = req.body as { emails: string[] };
        logger.info(`inviting new users `);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        const emailService = appService.emailService;
        const redisService = appService.redisService;
        const templateService = appService.templateService;

        const emailSettings = await configService.getEmailSetting();
        if (emailSettings.type == 'empty') {
            throw new RestfullException(400, ErrorCodes.ErrEmailConfigNeed, ErrorCodes.ErrEmailConfigNeed, "email config needs");
        }


        let results: { email: string, errMsg?: string }[] = [];
        for (const email of emails) {
            logger.info(`inviting ${email}`)
            try {
                const isEmail = await inputService.isEmail(email);
                if (!isEmail) {
                    results.push({ email: email, errMsg: 'not valid email' });
                    continue;
                }
                const userDb = await configService.getUserByUsername(email);
                if (userDb) {
                    results.push({ email: email, errMsg: 'allready exists' });
                    continue;
                }

                const key = Util.createRandomHash(48);
                const link = `${req.baseHost}/register/invite?key=${key}`
                await redisService.set(`/register/invite/${key}`, { email: email }, { ttl: 7 * 24 * 60 * 60 * 1000 })//1 days

                const logoPath = (await configService.getLogo()).defaultPath || 'logo.png';
                const logo = `${req.baseHost}/dassets/img/${logoPath}`;
                const html = await templateService.createInvite(email, link, logo);
                logger.info(`sending invite link to ${email}`);
                await emailService.send({ to: email, subject: `You are invited to join ${req.hostname}`, html: html });
                results.push({ email: email })

            } catch (err: any) {
                logger.error(err);
                results.push({ email: email, errMsg: err.message })
            }
        }


        return res.status(200).json({ results: results });

    }))

/////////////////////////////sensitive data //////////////////


async function getSensitiveData(configService: ConfigService, userId: string, isApiKey: boolean, isCert: boolean) {
    const data = await configService.getUserSensitiveData(userId);
    //dont send not needed data, becarefull returning data
    const retData = {
        apiKey: data.apiKey ? {
            ...data.apiKey
        } : undefined,
        cert: data.cert ? {
            ...data.cert
        } : undefined
    }
    //only needed data
    if (!isApiKey)
        delete retData.apiKey;
    if (!isCert)
        delete retData.cert;
    return retData;
}

routerUserAuthenticated.get('/:id/sensitiveData',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const queryApiKey = req.query.apiKey == 'true';
        const queryCert = req.query.cert == 'true';

        logger.info(`getting user sensitive data`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const retData = await getSensitiveData(configService, id, queryApiKey, queryCert);
        return res.status(200).json(retData);

    }))

interface InputChangeApiKeyAndCert {
    apiKey?: { key: string },
    cert?: SSLCertificate
}

async function changeApiKeyandCert(currentUser: User, configService: ConfigService,
    id: string, input: InputChangeApiKeyAndCert,
    auditService: AuditService, currentSession: AuthSession) {
    const user = await configService.getUserById(id);
    if (!user)
        throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNotFound, "not found");
    let before = { username: currentUser.username } as any;
    let after = { username: currentUser.username } as any;
    const dataBefore = await configService.getUserSensitiveData(id);
    let changeApiKey = false;
    if (input.apiKey) {//change apikey
        changeApiKey = true;
        //for audit log


        const apiKeyNew = dataBefore.apiKey ? {
            ...dataBefore.apiKey
        } : {};
        apiKeyNew.key = `${id}` + Util.randomNumberString(64);
        user.apiKey = apiKeyNew;

        //for audit log
        before.apikey = dataBefore.apiKey?.key ? "a key" : null;
        after.apikey = "new key";


    }

    let changeCert = false;
    if (input.cert) {//change cert
        changeCert = true;


        const certNew: SSLCertificateBase = dataBefore.cert ? {
            ...dataBefore.cert,
            category: 'auth'
        } : { category: 'auth' };
        const parentId = input.cert?.parentId || dataBefore.cert?.parentId || (await configService.getInSSLCertificateAllSensitive()).filter(x => x.category == 'auth').at(0)?.id || '';
        const inCert = await configService.getInSSLCertificateSensitive(parentId);
        if (!inCert || !inCert.isEnabled)
            throw new RestfullException(400, ErrorCodes.ErrCertificateIsNotValid, ErrorCodes.ErrCertificateIsNotValid, "cert not found or is not enabled");
        //1 year certificate
        const { publicCrt, privateKey } = await UtilPKI.createCertSigned(user.id, 'ferrumgate', 3650, false, [], inCert.publicCrt, inCert.privateKey);
        certNew.parentId = parentId;
        certNew.publicCrt = publicCrt;
        certNew.privateKey = privateKey;
        user.cert = certNew;

        //for audit log, dont write publicCrt, it is autmatically deleting
        before.publicCert = dataBefore.cert?.publicCrt ? "a certificate" : null;
        after.publicCert = "new certificate";

    }

    if (changeApiKey || changeCert) {
        await configService.saveUser(user);
        await auditService.logSensitiveData(currentSession, currentUser, before, after);
    }
    return { changeApiKey, changeCert };

}
routerUserAuthenticated.put('/:id/sensitiveData',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const input = req.body as InputChangeApiKeyAndCert;

        logger.info(`updating user sensitive data`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const { changeApiKey, changeCert } = await changeApiKeyandCert(currentUser, configService, id, input, auditService, currentSession);

        const retData = await getSensitiveData(configService, id, changeApiKey, changeCert);
        return res.status(200).json(retData);


    }))



routerUserAuthenticated.delete('/:id/sensitiveData',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const deleteApiKey = req.query.apiKey == 'true';
        const deleteCert = req.query.cert == 'true';


        logger.info(`updating user sensitive data`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const user = await configService.getUserById(id);
        if (!user)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNotFound, "not found");
        let before = { username: currentUser.username } as any;
        let after = { username: currentUser.username } as any;

        const dataBefore = await configService.getUserSensitiveData(id);

        let changeApiKey = false;
        if (deleteApiKey) {//delete apikey


            //for audit log

            if (dataBefore.apiKey?.key) {
                //this log will not written, apiKey is automatically removed
                before.apikey = "a key"
                after.apikey = undefined;

                changeApiKey = true;
                //reset apikey data
                user.apiKey = { key: '' };
            }


        }

        let changeCert = false;
        if (deleteCert) {//change cert


            //for audit log

            if (dataBefore.cert?.publicCrt) {
                before.publicCert = "a certificate"
                after.publicCert = undefined;

                changeCert = true;
                //reset cert data
                user.cert = { category: 'auth', parentId: '', privateKey: '', publicCrt: '' }
            }
        }

        if (changeApiKey || changeCert) {
            await configService.saveUser(user);
            await auditService.logSensitiveData(currentSession, currentUser, before, after);
        }

        const retData = await getSensitiveData(configService, id, changeApiKey, changeCert);
        return res.status(200).json(retData);


    }))







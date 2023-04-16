import express from "express";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import passport from "passport";
import { ConfigService } from "../service/configService";
import { RBACDefault } from "../model/rbac";
import { saveSystemDnsService } from "./serviceApi";
import { AuthSession } from "../model/authSession";
import { resetWebCertificate } from "./pkiApi";



interface Configure {
    email: string;
    password: string;
    domain: string;
    url: string;
    clientNetwork: string;
    serviceNetwork: string;
    sshHost: string;
}


/////////////////////////////////  configure //////////////////////////////////
export const routerConfigureAuthenticated = express.Router();

routerConfigureAuthenticated.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt']),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`configuring system for startup`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;
        //check user must admin, and system must not be configured before
        const user = req.currentUser as User;
        if (user.username !== 'admin') {
            logger.error(`current user is not admin`)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodes.ErrDataVerifyFailed, "not authorized");
        }
        const currentSession = req.currentSession as AuthSession;
        const roles = await configService.getUserRoles(user);
        if (!roles.find(x => x.id == RBACDefault.roleAdmin.id)) {
            logger.error(`current user role is not admin`)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodes.ErrNotEnoughRight, "not authorized");
        }

        const isConfiguredBefore = await configService.getIsConfigured();
        if (isConfiguredBefore) {
            logger.error("system is allready configured");
            throw new RestfullException(405, ErrorCodes.ErrAllreadyConfigured, ErrorCodes.ErrAllreadyConfigured, "allready configured system");
        }

        //check data
        const data = req.body as Configure;
        if (!data.email || !data.password || !data.domain || !data.url || !data.serviceNetwork || !data.clientNetwork) {
            logger.error("input data is not valid");
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "bad argument");
        }
        if (!data.sshHost) {
            logger.error("input data is not valid");
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "bad argument");
        }

        //check email and password 
        await inputService.checkEmail(data.email);
        await inputService.checkPasswordPolicy(data.password);

        // check other fields
        await inputService.checkDomain(data.domain);
        await inputService.checkUrl(data.url);
        await inputService.checkCidr(data.serviceNetwork);
        await inputService.checkCidr(data.clientNetwork);
        await inputService.checkHost(data.sshHost);

        const adminUser = await configService.getUserByUsername('admin');
        if (!adminUser) {
            logger.fatal("no admin user for configure");
            throw new RestfullException(412, ErrorCodes.ErrInternalError, ErrorCodesInternal.ErrAdminUserNotFound, "no admin user");
        }
        let aUserExistsWithThisEmail = await configService.getUserByUsername(data.email);
        if (aUserExistsWithThisEmail) {
            logger.fatal(`a user exists with ${data.email} allready exitsts at configure`);
            throw new RestfullException(412, ErrorCodes.ErrAllreadyExits, ErrorCodes.ErrAllreadyExits, "allready exists user");
        }
        await configService.setIsConfigured(1);
        await configService.changeAdminUser(data.email, data.password);
        await configService.setDomain(data.domain);
        await configService.setUrl(data.url);

        const defaultNetwork = await configService.getNetworkByName('default');
        if (!defaultNetwork) {
            logger.fatal(`no default network`);
            throw new RestfullException(412, ErrorCodes.ErrInternalError, ErrorCodesInternal.ErrNetworkNotFound, "no default network");
        }



        defaultNetwork.clientNetwork = data.clientNetwork;
        defaultNetwork.serviceNetwork = data.serviceNetwork;
        defaultNetwork.sshHost = data.sshHost;
        await configService.saveNetwork(defaultNetwork);

        const gateways = await configService.getGatewaysAll();
        const notJoined = gateways.find(x => !x.networkId)
        if (notJoined) {
            notJoined.networkId = defaultNetwork.id;
            await configService.saveGateway(notJoined);
        }


        //save default dns
        await saveSystemDnsService(defaultNetwork, configService, auditService, currentSession, user);
        //reset default web cert
        await resetWebCertificate(configService, auditService, currentSession, user);

        return res.status(200).json({});

    }))


import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportInit } from "./auth/passportInit";
import passport from "passport";
import { ConfigService } from "../service/configService";
import { RBACDefault } from "../model/rbac";


interface Configure {
    email: string;
    password: string;
    domain: string;
    url: string;
    clientNetwork: string;
    serviceNetwork: string;
}


/////////////////////////////////  configure //////////////////////////////////
export const routerConfigureAuthenticated = express.Router();

routerConfigureAuthenticated.post('/',
    asyncHandler(passportInit),
    passport.authenticate(['jwt'], { session: false, }),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`configuring system for startup`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        //check user must admin, and system must not be configured before
        const user = req.currentUser as User;
        if (user.username !== 'admin') {
            logger.error(`current user is not admin`)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, "not authorized");
        }
        if (!user.roleIds?.find(x => x == RBACDefault.roleAdmin.id)) {
            logger.error(`current user role is not admin`)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, "not authorized");
        }

        const isConfiguredBefore = await configService.getIsConfigured();
        if (!isConfiguredBefore) {
            logger.error("system is allready configured");
            throw new RestfullException(500, ErrorCodes.ErrAllreadyConfigured, "allready configured system");
        }

        //check data
        const data = req.body as Configure;
        if (!data.email || !data.password || !data.domain || !data.url || !data.serviceNetwork || !data.clientNetwork) {
            logger.error("input data is not valid");
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, "bad argument");
        }

        //check email and password 
        await inputService.checkEmail(data.email);
        await inputService.checkPasswordPolicy(data.password);

        // check other fields
        await inputService.checkDomain(data.domain);
        await inputService.checkUrl(data.url);
        await inputService.checkCidr(data.serviceNetwork);
        await inputService.checkCidr(data.clientNetwork);


        const adminUser = await configService.getUserByUsername('admin');
        if (!adminUser) {
            logger.fatal("no admin user for configure");
            throw new RestfullException(500, ErrorCodes.ErrInternalError, "no admin user");
        }
        await configService.setIsConfigured(1);
        await configService.changeAdminUser(data.email, data.password);
        await configService.setDomain(data.domain);
        await configService.setUrl(data.url);

        const defaultNetwork = await configService.getNetworkByName('default');
        if (!defaultNetwork) {
            logger.fatal(`no default network`);
            throw new RestfullException(500, ErrorCodes.ErrInternalError, "no default network");
        }

        defaultNetwork.clientNetwork = data.clientNetwork;
        defaultNetwork.serviceNetwork = data.serviceNetwork;

        await configService.setNetwork(defaultNetwork);

        return res.status(200).json({});

    }))


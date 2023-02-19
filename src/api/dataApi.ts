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
import { authorizeAsAdmin, authorizeAsAdminOrReporter } from "./commonApi";
import { cloneNetwork, Network } from "../model/network";
import { AuthSession } from "../model/authSession";
import { Countries } from "../model/country";


/////////////////////////////////  data //////////////////////////////////
export const routerDataAuthenticated = express.Router();





routerDataAuthenticated.get('/country',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting country list`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        return res.status(200).json({ items: Countries });

    }))

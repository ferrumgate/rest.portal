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



/////////////////////////////////  configure //////////////////////////////////
export const routerConfigureAuthenticated = express.Router();

routerConfigureAuthenticated.post('/',
    asyncHandler(passportInit),
    passport.authenticate(['jwt'], { session: false, }),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`configuring system for startup`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        return res.status(200).json({});

    }))


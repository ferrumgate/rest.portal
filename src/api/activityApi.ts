import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
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
import { SearchActivityLogsRequest } from "../service/esService";


/////////////////////////////////  activity //////////////////////////////////
export const routerActivityAuthenticated = express.Router();

routerActivityAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdminOrReporter),
    asyncHandler(async (req: any, res: any, next: any) => {
        const query = req.query as SearchActivityLogsRequest;
        logger.info(`getting activity logs`);
        const appService = req.appService as AppService;
        const auditService = appService.auditService;
        const activityService = appService.activityService;


        const data = await activityService.search(query);
        return res.status(200).json({ total: data.total, page: query.page, pageSize: query.pageSize, items: data.items });

    }))









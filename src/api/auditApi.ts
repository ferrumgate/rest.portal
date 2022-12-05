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


/////////////////////////////////  audit //////////////////////////////////
export const routerAuditAuthenticated = express.Router();

routerAuditAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdminOrReporter),
    asyncHandler(async (req: any, res: any, next: any) => {
        const startDate = req.query.startDate;
        const endDate = req.query.endDate;
        const search = req.query.search;
        const username = req.query.username;
        const message = req.query.message;
        const page = req.query.page;
        const pageSize = req.query.pageSize;
        logger.info(`getting audit logs`);
        const appService = req.appService as AppService;
        const auditService = appService.auditService;


        const data = await auditService.search(
            {
                startDate,
                endDate,
                search,
                username, message,
                page, pageSize
            }
        );
        return res.status(200).json({ total: data.total, page: page, pageSize: pageSize, items: data.items });

    }))









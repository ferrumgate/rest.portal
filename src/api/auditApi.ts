import express from "express";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import { authorizeAsAdminOrReporter } from "./commonApi";


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









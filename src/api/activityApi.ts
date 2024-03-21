import express from "express";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { SearchActivityLogsRequest } from "../service/esService";
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import { authorizeAsAdminOrReporter } from "./commonApi";


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









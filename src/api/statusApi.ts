import express from "express";
import { asyncHandler, logger } from "../common";
import { AppService } from "../service/appService";



/////////////////////////////////  status //////////////////////////////////
export const routerStatus = express.Router();
//no authenticaton, public api
routerStatus.get('/', asyncHandler(async (req: any, res: any, next: any) => {

    logger.info(`getting health status`);
    const appService = req.appService as AppService;
    const configService = appService.configService;
    return res.status(200).json({ isAlive: true });
}))


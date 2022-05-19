import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';



/////////////////////////////////  public //////////////////////////////////
export const routerConfig = express.Router();
///   /config/public
routerConfig.get('/', asyncHandler(async (req: any, res: any, next: any) => {

    logger.info(`getting public config`);
    const appService = req.appService as AppService;
    const configService = appService.configService;

    const captcha = await configService.getCaptcha();

    return res.status(200).json({ captchaSiteKey: captcha.client });

}))
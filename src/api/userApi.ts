import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';

export const routerUserConfirm = express.Router();

routerUserConfirm.get('/:key', asyncHandler(async (req: any, res: any, next: any) => {
    const key = req.params.key;

    const appService = req.appService as AppService;
    const configService = appService.configService;
    const redisService = appService.redisService;
    //check key from redis
    const rkey = `account_confirm_${key}`;
    const userId = await redisService.get(rkey, false) as string;
    if (!userId) {
        throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, "not found key");
    }
    const userDb = await configService.getUserById(userId);
    if (!userDb) {//check for safety
        throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, "argument problem");
    }
    //verify
    userDb.isVerified = true;
    await configService.saveUser(userDb);
    //delete the key for security
    await redisService.delete(rkey);
    return res.status(200).json({ result: true });

}))


export const routerUserResetPassword = express.Router();



import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportInit } from "./auth/passportInit";
import passport from "passport";
import { RBACDefault } from "../model/rbac";
import { config } from "process";
import { Tunnel } from "../model/tunnel";
import { TunnelService } from "../service/tunnelService";
import { HelperService } from "../service/helperService";







//////////////////////////////// authenticated tunnel  /////////////////////


export const routerClientTunnelAuthenticated = express.Router();

routerClientTunnelAuthenticated.get('/ip',
    asyncHandler(passportInit),
    passport.authenticate(['headertunnelkey'], { session: false, }),
    asyncHandler(async (req: any, res: any, next: any) => {
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const user = req.currentUser as User;
        const tunnel = req.currentTunnel as Tunnel;

        return res.status(200).json(
            { assignedIp: tunnel.assignedClientIp, serviceNetwork: await configService.getServiceNetwork() }
        );
    })
);

/**
 * client needs a new ip because of conflict
 */
routerClientTunnelAuthenticated.get('/renewip',
    asyncHandler(passportInit),
    passport.authenticate(['headertunnelkey'], { session: false, }),
    asyncHandler(async (req: any, res: any, next: any) => {
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const redisService = appService.redisService;
        const tunnelService = appService.tunnelService;
        const user = req.currentUser as User;
        const tunnel = req.currentTunnel as Tunnel;
        HelperService.isValidTunnel(tunnel);

        const newtunnel = await tunnelService.renewIp(tunnel.id || '', redisService);

        return res.status(200).json({
            assignedIp: newtunnel.assignedClientIp, serviceNetwork: await configService.getServiceNetwork()
        });
    })
);

/**
 * @summary after client created tunnel successfuly, it confirms 
 */
routerClientTunnelAuthenticated.post('/confirm',
    asyncHandler(passportInit),
    passport.authenticate(['headertunnelkey'], { session: false, }),
    asyncHandler(async (req: any, res: any, next: any) => {
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const redisService = appService.redisService;
        const tunnelService = appService.tunnelService;
        const user = req.currentUser as User;
        const tunnel = req.currentTunnel as Tunnel;
        await tunnelService.confirm(tunnel.id || '', redisService);

        return res.status(200).json({});
    })
);

/**
 * @summary every client sends i am alive request
 */
routerClientTunnelAuthenticated.get('/alive',
    asyncHandler(passportInit),
    passport.authenticate(['headertunnelkey'], { session: false, }),
    asyncHandler(async (req: any, res: any, next: any) => {
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const user = req.currentUser as User;
        const tunnel = req.currentTunnel as Tunnel;
        const redisService = appService.redisService;
        const tunnelService = appService.tunnelService;
        await tunnelService.alive(tunnel.id || '', redisService);

        return res.status(200).json({});
    })
);



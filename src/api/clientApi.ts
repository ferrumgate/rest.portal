import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import passport from "passport";
import { RBACDefault } from "../model/rbac";
import { config } from "process";
import { Tunnel } from "../model/tunnel";
import { TunnelService } from "../service/tunnelService";
import { HelperService } from "../service/helperService";
import { getNetworkByGatewayId } from "./commonApi";
import { AuthSession } from "../model/authSession";
import { attachActivity, attachActivitySession, attachActivityTunnel, attachActivityUser, saveActivity, saveActivityError } from "./auth/commonAuth";







//////////////////////////////// authenticated tunnel  /////////////////////


export const routerClientTunnelAuthenticated = express.Router();

routerClientTunnelAuthenticated.get('/ip',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['tunnelKey']),
    asyncHandler(async (req: any, res: any, next: any) => {
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const user = req.currentUser as User;
        const tunnel = req.currentTunnel as Tunnel;

        const network = await getNetworkByGatewayId(configService, tunnel.gatewayId);
        return res.status(200).json(
            { assignedIp: tunnel.assignedClientIp, serviceNetwork: network.serviceNetwork }
        );
    })
);

/**
 * client needs a new ip because of conflict
 */
routerClientTunnelAuthenticated.get('/renewip',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['tunnelKey']),
    asyncHandler(async (req: any, res: any, next: any) => {
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const redisService = appService.redisService;
        const tunnelService = appService.tunnelService;
        const user = req.currentUser as User;
        const tunnel = req.currentTunnel as Tunnel;
        HelperService.isValidTunnel(tunnel);
        const network = await getNetworkByGatewayId(configService, tunnel.gatewayId);
        const newtunnel = await tunnelService.renewIp(tunnel.id || '');

        return res.status(200).json({
            assignedIp: newtunnel.assignedClientIp, serviceNetwork: network.serviceNetwork
        });
    })
);


routerClientTunnelAuthenticated.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt']),
    asyncHandler(async (req: any, res: any, next: any) => {
        let tunnel: Tunnel | undefined;
        try {
            const appService = req.appService as AppService;
            const configService = appService.configService;
            const policyService = appService.policyService;
            const inputService = appService.inputService;
            const tunnelService = appService.tunnelService;
            const systemlogService = appService.systemLogService;

            const user = req.currentUser as User;
            attachActivityUser(req, user);
            const session = req.currentSession as AuthSession;
            attachActivitySession(req, session);

            const tunnelKey = req.body.tunnelKey || req.query.tunnelKey;
            logger.info(`creating tunnel for ${tunnelKey}`);
            attachActivityTunnel(req, { id: tunnelKey } as Tunnel);

            await inputService.checkIfExists(tunnelKey);
            await inputService.checkStringLength(tunnelKey, 63);
            HelperService.isValidUser(user);
            HelperService.isValidSession(session);

            //for better logging
            tunnel = await tunnelService.getTunnel(tunnelKey);
            attachActivityTunnel(req, tunnel);

            const rule = await policyService.authenticate(user, session.is2FA, tunnel);
            tunnel = await tunnelService.createTunnel(user, tunnelKey, session);
            await systemlogService.write({ path: '/system/tunnels/create', type: 'put', val: tunnel });
            attachActivityTunnel(req, tunnel);

            await saveActivity(req, 'create tunnel', (log) => {
                log.authnRuleId = rule.id;
                log.authnRuleName = rule.name;

            });

            return res.status(200).json({});

        } catch (err) {
            await saveActivityError(req, 'create tunnel', err, (log) => {

            });
            throw err;
        }
    })
);

/**
 * @summary after client created tunnel successfuly, it confirms 
 */
routerClientTunnelAuthenticated.post('/confirm',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['tunnelKey']),
    asyncHandler(async (req: any, res: any, next: any) => {
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const redisService = appService.redisService;
        const tunnelService = appService.tunnelService;
        const user = req.currentUser as User;
        const tunnel = req.currentTunnel as Tunnel;
        const systemlogService = appService.systemLogService;
        await tunnelService.confirm(tunnel.id || '');
        await systemlogService.write({ path: '/system/tunnels/confirm', 'type': 'put', val: tunnel });
        return res.status(200).json({});
    })
);

/**
 * @summary every client sends i am alive request
 */
routerClientTunnelAuthenticated.get('/alive',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['tunnelKey']),
    asyncHandler(async (req: any, res: any, next: any) => {
        try {
            const appService = req.appService as AppService;
            const configService = appService.configService;
            const redisService = appService.redisService;
            const tunnelService = appService.tunnelService;
            const systemlogService = appService.systemLogService;
            const user = req.currentUser as User;
            attachActivityUser(req, user);
            const session = req.currentSession as AuthSession;
            attachActivitySession(req, session);
            const tunnel = req.currentTunnel as Tunnel;
            attachActivityTunnel(req, tunnel);
            logger.info(`i am alive tunnel: ${tunnel.id}`);
            await tunnelService.alive(tunnel.id || '');
            await systemlogService.write({ path: '/system/tunnels/alive', 'type': 'put', val: tunnel });
            //await saveActivity(req, 'tunnel alive');

            return res.status(200).json({});
        } catch (err) {
            await saveActivityError(req, 'tunnel alive', err);
            throw err;
        }
    })
);



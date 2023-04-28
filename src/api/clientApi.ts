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
import { Gateway } from "../model/network";
import { Network } from "../model/network";
import { ClientDevicePosture, DeviceLog } from "../model/device";








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
        const services = await configService.getServicesByNetworkId(network.id);
        const rootFqdn = await configService.getDomain();
        const dnsService = services.find(x => x.isSystem && x.protocol == 'dns');
        return res.status(200).json(
            {
                assignedIp: tunnel.assignedClientIp, serviceNetwork: network.serviceNetwork,
                resolvIp: dnsService?.assignedIp, resolvSearch: `${network.name}.${rootFqdn}`
            }
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
        let gateway: Gateway | undefined;
        let network: Network | undefined;
        let devicePosture: ClientDevicePosture | undefined;
        let appService: AppService | undefined;
        let deviceLog: DeviceLog | undefined;
        try {
            appService = req.appService as AppService;
            const configService = appService.configService;
            const policyService = appService.policyService;
            const inputService = appService.inputService;
            const tunnelService = appService.tunnelService;
            const systemlogService = appService.systemLogService;
            const deviceService = appService.deviceService;

            const user = req.currentUser as User;
            attachActivityUser(req, user);
            const session = req.currentSession as AuthSession;
            attachActivitySession(req, session);

            const tunnelKey = req.body.tunnelKey || req.query.tunnelKey;
            logger.info(`creating tunnel for ${tunnelKey}`);
            attachActivityTunnel(req, { id: tunnelKey } as Tunnel);

            devicePosture = await deviceService.getDevicePosture(session.deviceId || '');
            if (devicePosture)
                deviceLog = await deviceService.convertDevicePostureToDeviceLog(devicePosture, user.id || '', user.username || '');

            await inputService.checkIfExists(tunnelKey);
            await inputService.checkStringLength(tunnelKey, 63);

            //for better logging
            tunnel = await tunnelService.getTunnel(tunnelKey);
            attachActivityTunnel(req, tunnel);
            //get gateway and network for better
            if (tunnel?.gatewayId) {
                gateway = await configService.getGateway(tunnel.gatewayId);
                if (gateway?.networkId)
                    network = await configService.getNetwork(gateway?.networkId);
            }

            HelperService.isValidUser(user);
            HelperService.isValidSession(session);



            const rule = await policyService.authenticate(user, session, tunnel, devicePosture);
            tunnel = await tunnelService.createTunnel(user, tunnelKey, session);

            if (deviceLog)
                await deviceService.save(deviceLog);
            await systemlogService.write({ path: '/system/tunnels/create', type: 'put', val: tunnel });
            attachActivityTunnel(req, tunnel);

            await saveActivity(req, 'create tunnel', (log) => {
                log.authnRuleId = rule.id;
                log.authnRuleName = rule.name;
                log.gatewayId = gateway?.id;
                log.gatewayName = gateway?.name;
                log.networkId = network?.id;
                log.networkName = network?.name;

            });

            return res.status(200).json({});

        } catch (err: any) {


            //try to save device posture
            if (deviceLog && appService)
                try {
                    deviceLog.isHealthy = false;
                    deviceLog.whyNotHealthy = err.codeInternal || 'ErrDevicePostureNotChecked';
                    await appService.deviceService.save(deviceLog);
                } catch (ignore) {
                    console.log(ignore);
                }

            await saveActivityError(req, 'create tunnel', err, (log) => {
                log.gatewayId = gateway?.id;
                log.gatewayName = gateway?.name;
                log.networkId = network?.id;
                log.networkName = network?.name;
                log.deviceId = devicePosture?.clientId;
                log.deviceName = devicePosture?.hostname;

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



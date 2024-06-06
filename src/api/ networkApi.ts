import express from "express";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AuthSession } from "../model/authSession";
import { AuthorizationRule, cloneAuthorizationRule } from "../model/authorizationPolicy";
import { Network, cloneNetwork } from "../model/network";
import { User } from "../model/user";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { AppService } from "../service/appService";
import { AuditService } from "../service/auditService";
import { ConfigService } from "../service/configService";
import { Util } from "../util";
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import { authorizeAsAdmin } from "./commonApi";
import { getEmptyServiceIp, saveSystemDnsService } from "./serviceApi";


/////////////////////////////////  network //////////////////////////////////
export const routerNetworkAuthenticated = express.Router();





routerNetworkAuthenticated.get('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting network with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const network = await configService.getNetwork(id);
        if (!network) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNetworkNotFound, 'no network');

        //const gateways = await configService.getGatewaysByNetworkId(network.id);

        return res.status(200).json(network);

    }))

routerNetworkAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        const ids = req.query.ids as string;
        logger.info(`query network`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        let items: Network[] = [];
        if (search) {
            const networks = await configService.getNetworksBy(search.toLowerCase());
            items = items.concat(networks);

        } else
            if (ids) {
                const parts = ids.split(',');
                for (const id of parts) {
                    const network = await configService.getNetwork(id);
                    if (network)
                        items.push(network);
                }

            } else
                items = await configService.getNetworksAll();

        return res.status(200).json({ items: items });

    }))

routerNetworkAuthenticated.delete('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete network with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const network = await configService.getNetwork(id);
        if (!network) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNetworkNotFound, 'no network');

        const { before } = await configService.deleteNetwork(network.id);
        await auditService.logDeleteNetwork(currentSession, currentUser, before);
        return res.status(200).json({});

    }))



routerNetworkAuthenticated.put('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as Network;
        logger.info(`changing network settings for ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkNotEmpty(input.id);
        const network = await configService.getNetwork(input.id);
        if (!network) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrNetworkNotFound, 'no network');

        await inputService.checkDomain(input.name);

        await inputService.checkCidr(input.clientNetwork);
        await inputService.checkCidr(input.serviceNetwork);
        if (input.sshHost)
            await inputService.checkHost(input.sshHost);
        /* if (input.openVpnHost)
              await inputService.checkHost(input.openVpnHost);
          if (input.wireguardHost)
              await inputService.checkHost(input.wireguardHost); */
        input.name = input.name || 'network';
        input.labels = input.labels || [];
        const safe = cloneNetwork(input);
        safe.insertDate = network.insertDate;
        safe.updateDate = new Date().toISOString();

        if (network.serviceNetwork != safe.serviceNetwork)//service network changed
        {
            let usedIps: string[] = []
            const allServicesFromThisNetwork = await configService.getServicesByNetworkId(safe.id);
            const dns = allServicesFromThisNetwork.find(x => x.isSystem && x.protocol == 'dns');
            if (dns) {//first dns service
                dns.assignedIp = getEmptyServiceIp(safe, []);
                await configService.saveService(dns);
                usedIps.push(dns.assignedIp);
            }

            for (const svc of allServicesFromThisNetwork) {
                if (svc.id != dns?.id) {
                    svc.assignedIp = getEmptyServiceIp(safe, usedIps);
                    await configService.saveService(svc);
                    usedIps.push(svc.assignedIp);
                }
            }

        }


        const { before, after } = await configService.saveNetwork(safe);
        await auditService.logSaveNetwork(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerNetworkAuthenticated.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new network`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const input = req.body as Network;
        input.id = Util.randomNumberString(16);

        await inputService.checkDomain(input.name);
        await inputService.checkCidr(input.clientNetwork);
        await inputService.checkCidr(input.serviceNetwork);
        if (input.sshHost)
            await inputService.checkHost(input.sshHost);
        /*   if (input.openVpnHost)
              await inputService.checkHost(input.openVpnHost);
          if (input.wireguardHost)
              await inputService.checkHost(input.wireguardHost); */
        input.name = input.name || 'network';
        input.labels = input.labels || [];
        const safe = cloneNetwork(input);
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveNetwork(safe);
        await auditService.logSaveNetwork(currentSession, currentUser, before, after);


        //create default dns service
        await saveSystemDnsService(safe, configService, auditService, currentSession, currentUser);

        //create access rule to dns service for everyone
        await saveDefaultDnsServiceAuthorizationForEverybody(safe, configService, auditService, currentSession, currentUser);


        return res.status(200).json(safe);

    }))

/**
* @summary give permission to everybody
*/
export async function saveDefaultDnsServiceAuthorizationForEverybody(network: Network, configService: ConfigService,
    auditService: AuditService, currentSession: AuthSession, currentUser: User) {
    //create default dns service
    const services = await configService.getServicesByNetworkId(network.id);
    const dnsService = services.find(x => x.isSystem && x.protocol == 'dns');
    if (!dnsService) {
        logger.warn("system dns service not found");
        return;
    }
    const authorizationRule: AuthorizationRule = {
        id: Util.randomNumberString(16),
        name: "everybody-can-access",
        insertDate: new Date().toISOString(),
        isEnabled: true,
        networkId: network.id,
        serviceId: dnsService.id,
        profile: { is2FA: false },
        updateDate: new Date().toISOString(),
        userOrgroupIds: []

    }
    const safe = cloneAuthorizationRule(authorizationRule);
    //copy original one
    const { before, after } = await configService.saveAuthorizationPolicyRule(safe);
    //await configService.updateAuthorizationPolicyUpdateTime();
    await auditService.saveAuthorizationPolicyRule(currentSession, currentUser, before, after);

}







import express from "express";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import passport from "passport";
import { ConfigService } from "../service/configService";
import { RBACDefault } from "../model/rbac";
import { authorizeAsAdmin } from "./commonApi";
import { cloneService, Service } from "../model/service";
import { Network } from "../model/network";
import { AuditService } from "../service/auditService";
import { AuthSession } from "../model/authSession";
import { AuthorizationRule, cloneAuthorizationRule } from "../model/authorizationPolicy";



/////////////////////////////////  service //////////////////////////////////
export const routerServiceAuthenticated = express.Router();



routerServiceAuthenticated.get('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting service with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const service = await configService.getService(id);
        if (!service) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrServiceNotFound, 'no service');


        return res.status(200).json(service);

    }))

routerServiceAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const search = req.query.search;
        const ids = Util.convertToArray(req.query.ids);
        const networkIds = Util.convertToArray(req.query.networkIds);
        logger.info(`query services with ${JSON.stringify(req.query)}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        let items: Service[] = [];
        const services = await configService.getServicesBy(search, networkIds, ids);
        items = items.concat(services);
        return res.status(200).json({
            items: items
        });

    }))

routerServiceAuthenticated.delete('/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete service with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;
        const service = await configService.getService(id);
        if (!service) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrServiceNotFound, 'no service');

        if (service.isSystem)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrSystemServiceDelete, "you cannot delete system services");

        const { before } = await configService.deleteService(service.id);
        await auditService.logDeleteService(currentSession, currentUser, before);
        return res.status(200).json({});

    }))



routerServiceAuthenticated.put('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as Service;
        logger.info(`changing service settings for ${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkNotEmpty(input.id);
        const service = await configService.getService(input.id);
        if (!service) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrServiceNotFound, 'no service');


        input.name = input.name || 'service';
        input.labels = input.labels || [];
        if (!input.ports.some(x => x.port && (x.isTcp || x.isUdp))) {
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, 'input port is invalid');
        }
        if (!input.hosts.some(x => x.host)) {
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, 'input host is invalid');
        }
        await inputService.checkIfExists(input.networkId);
        const network = await configService.getNetwork(input.networkId);
        if (!network) {
            throw new RestfullException(400, ErrorCodes.ErrNetworkNotFound, ErrorCodesInternal.ErrNetworkNotFound, 'no network found');
        }
        await inputService.checkDomain(input.name);
        await inputService.checkIfExists(input.protocol);


        const safe = cloneService(input);
        //reassign allready assigned ip, system will manage it
        safe.assignedIp = service.assignedIp;

        //copy orijinal 
        safe.insertDate = service.insertDate;
        safe.updateDate = new Date().toISOString();
        if (service.isSystem) {//system services cannot change some fields
            safe.name = service.name;
            safe.networkId = service.networkId;
            safe.isEnabled = service.isEnabled;
            safe.isSystem = service.isSystem;
        }

        if (service.networkId != safe.networkId) {//network changed
            const targetNetwork = await configService.getNetwork(safe.networkId);
            if (!targetNetwork) {
                throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, 'target network not found');
            }
            const allServicesFromThisNetwork = await configService.getServicesByNetworkId(targetNetwork.id);
            safe.assignedIp = getEmptyServiceIp(network, allServicesFromThisNetwork.map(x => x.assignedIp));
            const policies = await configService.getAuthorizationPolicy();
            for (const pol of policies.rules) {
                if (pol.serviceId == service.id) {
                    if (pol.networkId != safe.networkId) {
                        pol.networkId = safe.networkId;
                        await configService.saveAuthorizationPolicyRule(pol);
                    }
                }
            }
        }

        const { before, after } = await configService.saveService(safe);
        await auditService.logSaveService(currentSession, currentUser, before, after);
        return res.status(200).json(safe);

    }))

routerServiceAuthenticated.post('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`saving a new service`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        const input = req.body as Service;
        input.id = Util.randomNumberString(16);


        input.name = input.name || 'service';
        input.labels = input.labels || [];
        if (!input.ports.some(x => x.port && (x.isTcp || x.isUdp))) {
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, 'input port is invalid');
        }
        if (!input.hosts.some(x => x.host)) {
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, 'input host is invalid');
        }
        await inputService.checkIfExists(input.networkId);
        const network = await configService.getNetwork(input.networkId);
        if (!network) {
            throw new RestfullException(400, ErrorCodes.ErrNetworkNotFound, ErrorCodesInternal.ErrNetworkNotFound, 'no network found');
        }
        await inputService.checkIfExists(input.protocol);

        await inputService.checkDomain(input.name);
        const safe = cloneService(input);
        const allServicesFromThisNetwork = await configService.getServicesByNetworkId(network.id);
        safe.assignedIp = getEmptyServiceIp(network, allServicesFromThisNetwork.map(x => x.assignedIp));
        safe.insertDate = new Date().toISOString();
        safe.updateDate = new Date().toISOString();
        const { before, after } = await configService.saveService(safe);
        await auditService.logSaveService(currentSession, currentUser, before, after);
        return res.status(200).json(safe);

    }))

/**
 * @summary create a dns service for network
 */
export async function saveSystemDnsService(network: Network, configService: ConfigService,
    auditService: AuditService, currentSession: AuthSession, currentUser: User) {
    //create default dns service
    const dnsService: Service = {
        id: Util.randomNumberString(16),
        name: 'dns',
        protocol: 'dns',
        isSystem: true,
        count: 1,
        networkId: network.id,
        hosts: [{ host: '1.1.1.1' }],
        ports: [{ port: 53, isTcp: false, isUdp: true }],
        assignedIp: getEmptyServiceIp(network, []),
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        isEnabled: true, labels: ['system']
    }
    const { before, after } = await configService.saveService(dnsService);
    await auditService.logSaveService(currentSession, currentUser, before, after);
}






export function getEmptyServiceIp(network: Network, usedIpList: string[]): string {


    const serviceCidr = network.serviceNetwork;
    if (!serviceCidr.includes('/')) {
        logger.error("config service network is not valid");
        throw new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodesInternal.ErrServiceCidrNotValid, "service network is not valid");
    }
    const parts = serviceCidr.split('/');
    const range = Util.ipCidrToRange(parts[0], Number(parts[1]));

    let start = Util.ipToBigInteger(range.start) + 1n;//for performance track last used ip
    let end = Util.ipToBigInteger(range.end);
    if (start >= end)// if all pool ips used, then start from beginning for search
        start = Util.ipToBigInteger(range.start);

    for (let s = start; s < end; s++) {
        const ip = Util.bigIntegerToIp(s);
        const isExists = usedIpList.includes(`${ip}`);
        if (!isExists) return ip;
    }

    logger.fatal("service ip pool is over");
    throw new RestfullException(500, ErrorCodes.ErrIpAssignFailed, ErrorCodesInternal.ErrIpPoolIsOver, 'ip pool is over');

}


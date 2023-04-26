import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { User } from "../model/user";
import { ConfigService } from "./configService";
import { TunnelService } from "./tunnelService";
import { AuditService } from "./auditService";
import { RedisService } from "../service/redisService";
import { Tunnel } from "../model/tunnel";
import { AuthenticationRule } from "../model/authenticationPolicy";
import { AuthorizationRule } from "../model/authorizationPolicy";
import ip from 'ip-cidr';
import { HelperService } from "./helperService";
import { logger } from "../common";
import { Gateway, Network } from "../model/network";
import { Service } from "../model/service";
import { AuthSession } from "../model/authSession";
import { Util } from "../util";
import { IpIntelligence } from "../model/IpIntelligence";
import { IpIntelligenceService } from "./ipIntelligenceService";
import { OSType } from "../model/authenticationProfile";


export interface UserNetworkListResponse {
    network: Network,
    action: 'deny' | 'allow',
    needs2FA?: boolean,
    needsIp?: boolean,
    needsGateway?: boolean;
    needsTime?: boolean;

}

export interface UserDevicePostureParameter {
    os: OSType;
    file?: { path: string };
    registry?: { path: string; key?: string };
    process?: { path: string };
}


export enum PolicyAuthzErrors {
    NoError,
    TunnelNotFound,
    TunnelNotValid,
    UserNotFound,
    UserNotValid,
    ServiceNotFound,
    ServiceNotValid,
    NetworkNotFound,
    NetworkNotValid,
    GatewayNotFound,
    GatewayNotValid,
    NoRuleMatch = 100,
    ClientNotFound = 10000,//ferrum.io project ferrum_policy.h 
    InvalidData = 10001,
    NotFound = 10002,
    ExecuteFailed = 10003,
    DisabledPolicy = 10004
}
export enum PolicyAuthnErrors {
    NoError,
    TunnelNotFound,
    TunnelNotValid,
    GatewayNotFound,
    GatewayNotValid,
    NetworkNotFound,
    NetworkNotValid,
    SessionNotFound,
    SessionNotValid,

    NoRuleMatch = 100
}


export interface PolicyAuthzResult {

    error: number, index?: number, rule?: AuthorizationRule
}
/**
 * @summary executes authentication and authorization policy rules, and returns a result
 */
export class PolicyService {
    /**
     *
     */
    constructor(private configService: ConfigService, private ipIntelligenceService: IpIntelligenceService
    ) {


    }

    /**
     * @summary check rule includes @param user
     */
    async isUserIdOrGroupIdAllowed(rule: AuthenticationRule | AuthorizationRule, user: User) {
        if (!rule.userOrgroupIds.length) return true;
        if (rule.userOrgroupIds.includes(user.id))
            return true;
        if (rule.userOrgroupIds.find(x => user.groupIds.includes(x)))
            return true;

        return false;

    }

    /**
     * @summary check if rule needs 2FA
     */
    async is2FA(rule: AuthenticationRule | AuthorizationRule, checkValue: boolean) {
        if (!rule.profile.is2FA) return true
        else
            if (checkValue) return true;
            else
                return false;

    }

    /**
     * @summary check if rule ips includes client ip
     */
    async isCustomWhiteListContains(rule: AuthenticationRule, clientIp: string) {
        if (!rule.profile.whiteListIps?.length) return false;
        const client = ip.createAddress(clientIp);
        for (const ipprofile of rule.profile.whiteListIps) {

            if (client.isInSubnet(ip.createAddress(ipprofile.ip)))
                return true;
        }
        return false;

    }

    /**
    * @summary check if rule ips includes client ip
    */
    async isCustomBlackListContains(rule: AuthenticationRule, clientIp: string) {
        if (!rule.profile.blackListIps?.length) return false;
        const client = ip.createAddress(clientIp);
        for (const ipprofile of rule.profile.blackListIps) {

            if (client.isInSubnet(ip.createAddress(ipprofile.ip)))
                return true;
        }
        return false;

    }

    /* /**
     * @summary  check if ip intelligence whitelist includes client ip
     */
    async isIpIntelligenceWhiteListContains(rule: AuthenticationRule, clientIp: string) {
        if (!rule.profile.ipIntelligence?.whiteLists?.length) return false;

        const items = await this.ipIntelligenceService.listService.getByIpAll(clientIp);
        for (const ite of rule.profile.ipIntelligence?.whiteLists) {
            if (items.items.includes(ite)) return true;
        }

        return false;
    }

    /**
     * @summary check if ip intelligence blacklist includes client ip
     */
    async isIpIntelligenceBlackListContains(rule: AuthenticationRule, clientIp: string) {
        if (!rule.profile.ipIntelligence?.blackLists?.length) return false;
        const items = await this.ipIntelligenceService.listService.getByIpAll(clientIp);
        for (const ite of rule.profile.ipIntelligence?.blackLists) {
            if (items.items.includes(ite)) return true;
        }
        return false;
    }

    /**
     * @summary check if ip is proxy ip or hosting ip or a crawler ip
     */
    async isIpIntelligenceBlackIp(rule: AuthenticationRule, session: AuthSession) {
        if (rule.profile.ipIntelligence?.isHosting && session.isHostingIp)
            return true;
        if (rule.profile.ipIntelligence?.isCrawler && session.isCrawlerIp)
            return true;
        if (rule.profile.ipIntelligence?.isProxy && session.isProxyIp)
            return true;
        return false;
    }



    /**
     * @summary check if ip country  
     */
    async isIpIntelligenceCountryContains(rule: AuthenticationRule, countryCode?: string) {
        if (!rule.profile.locations?.length) return true;
        if (!countryCode) return true;//local ip addresses
        if (rule.profile.locations?.find(x => x.countryCode == countryCode)) return true;
        return false;
    }

    /**
 * @summary check if ip country  
 */
    async isTimeAllowed(rule: AuthenticationRule) {
        if (!rule.profile.times?.length) return true;
        for (const zone of rule.profile.times) {
            const time = Util.timeInZone(zone.timezone);
            if (zone.days.includes(time.weekDay)) {
                let start = zone.startTime || 0;
                let end = zone.endTime || 24 * 60;
                let timeminute = time.hour * 60 + time.minute;
                if (start <= timeminute && timeminute <= end)
                    return true;
            }

        }

        return false;
    }

    async isIpIntelligenceAllowed(rule: AuthenticationRule, session: AuthSession, clientIp: string) {
        let ip = clientIp.split('#')[0];//ip can be like 1.2.3.4#34233 ip#port
        //check white lists
        if (await this.isCustomWhiteListContains(rule, ip))
            return true;
        // check ip intelligence lists
        if (await this.isIpIntelligenceWhiteListContains(rule, ip))
            return true;

        //check black lists
        if (await this.isCustomBlackListContains(rule, ip))
            return false;
        // check ip intelligence lists
        if (await this.isIpIntelligenceBlackListContains(rule, ip))
            return false;


        //check proxy ip
        if (await this.isIpIntelligenceBlackIp(rule, session))
            return false;

        //check country
        if (await this.isIpIntelligenceCountryContains(rule, session.countryCode))
            return true;

        return false;
    }



    errorNumber = PolicyAuthnErrors.NoError;
    /**
     * @summary check user can create a tunnel, check ips, etc...
     * @returns 
     */
    async authenticate(user: User, session: AuthSession | undefined, tunnel: Tunnel | undefined) {
        //get tunnel basic information
        this.errorNumber = PolicyAuthnErrors.NoError;
        //const tunnel = await this.tunnelService.getTunnel(tunnelKey);
        if (!tunnel) {
            this.errorNumber = PolicyAuthnErrors.TunnelNotFound;

            throw new RestfullException(401, ErrorCodes.ErrTunnelFailed, ErrorCodesInternal.ErrTunnelNotFoundOrNotValid, 'secure tunnel failed');
        }
        if (!tunnel.id || !tunnel.clientIp || !tunnel.gatewayId) {
            this.errorNumber = PolicyAuthnErrors.TunnelNotValid;

            throw new RestfullException(401, ErrorCodes.ErrTunnelFailed, ErrorCodesInternal.ErrTunnelNotFoundOrNotValid, 'secure tunnel failed');
        }

        if (!session) {
            this.errorNumber = PolicyAuthnErrors.SessionNotFound;

            throw new RestfullException(401, ErrorCodes.ErrTunnelFailed, ErrorCodesInternal.ErrUserSessionNotFoundInvalid, 'secure tunnel failed');
        }
        if (!session.id || !session.userId) {
            this.errorNumber = PolicyAuthnErrors.SessionNotValid;

            throw new RestfullException(401, ErrorCodes.ErrTunnelFailed, ErrorCodesInternal.ErrUserSessionNotFoundInvalid, 'secure tunnel failed');
        }

        const is2FAValidated = session.is2FA;


        const gateway = await this.configService.getGateway(tunnel.gatewayId);
        if (!gateway) {
            this.errorNumber = PolicyAuthnErrors.GatewayNotFound;

            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrGatewayNotFound, 'no gateway');
        }
        if (!gateway.isEnabled) {
            this.errorNumber = PolicyAuthnErrors.GatewayNotValid;

            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrGatewayNotValid, 'no gateway');
        }
        const network = await this.configService.getNetwork(gateway.networkId || '');
        if (!network) {
            this.errorNumber = PolicyAuthnErrors.NetworkNotFound;

            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrNetworkNotFound, 'no network');
        }

        if (!network.isEnabled) {
            this.errorNumber = PolicyAuthnErrors.NetworkNotValid;

            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrNetworkNotValid, 'no network');
        }
        //try to log more error code
        let error = ErrorCodesInternal.ErrNoRuleMatch;
        //logger.info(`policy authentication check ${JSON.stringify(session)}  ${JSON.stringify(tunnel)}}`);
        const policy = await this.configService.getAuthenticationPolicy();
        const rules = await policy.rules.filter(x => x.networkId == network.id);
        for (const rule of rules) {
            if (!rule.isEnabled)
                continue;
            let f1 = await this.isUserIdOrGroupIdAllowed(rule, user);
            let f2 = await this.is2FA(rule, is2FAValidated);
            let f3 = await this.isIpIntelligenceAllowed(rule, session, tunnel.clientIp);
            let f4 = await this.isTimeAllowed(rule);


            if (f1 && f2 && f3 && f4) {

                return rule;

            }
            if (f1) {
                if (!f2)
                    error = ErrorCodesInternal.ErrNo2FAMatch;
                else
                    if (!f3)
                        error = ErrorCodesInternal.ErrNoLocationMatch;
                    else error = ErrorCodesInternal.ErrNoTimeMatch;

            }

        }
        //no rule match
        this.errorNumber = PolicyAuthnErrors.NoRuleMatch;
        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, error, 'not authenticated');
    }

    /**
     * @summary find networks that user can connect or why not connect
     * @returns 
     */
    async userNetworks(user: User, session: AuthSession, clientIp: string) {

        this.errorNumber = 0;
        let result: UserNetworkListResponse[] = [];

        const networks = await this.configService.getNetworksAll();
        const policy = await this.configService.getAuthenticationPolicy();
        for (const network of networks) {


            if (!network) {
                this.errorNumber = 1;
                continue;
            }

            if (!network.isEnabled) {
                this.errorNumber = 5;
                continue;
            }


            const rules = await policy.rules.filter(x => x.networkId == network.id);
            for (const rule of rules) {
                if (!rule.isEnabled)
                    continue;
                let f1 = await this.isUserIdOrGroupIdAllowed(rule, user);
                let f2 = await this.is2FA(rule, session.is2FA);
                let f3 = await this.isIpIntelligenceAllowed(rule, session, clientIp);
                let f4 = await this.isTimeAllowed(rule);

                if (f1 && f2 && f3 && f4) {

                    const gateways = await this.configService.getGatewaysByNetworkId(network.id);
                    if (!gateways.find(x => x.isEnabled)) {
                        result.push({ network: network, action: 'deny', needsGateway: true });
                    } else
                        result.push({ network: network, action: 'allow', })
                    break


                } else if (f1) {
                    result.push(
                        {
                            network: network,
                            action: 'deny',
                            needs2FA: !f2,
                            needsIp: !f3,
                            needsTime: !f4
                        });
                    break;
                }
            }
        }

        return result;


    }

    /**
     * @summary find user dynamic device postures for calculation
     * @param user 
     * @param session 
     * @param clientIp 
     */
    async userDevicePostureParameters(user: User, session: AuthSession, clientIp: string) {
        this.errorNumber = 0;
        let result: UserDevicePostureParameter[] = [];

        const networks = await this.configService.getNetworksAll();
        const policy = await this.configService.getAuthenticationPolicy();
        const devicePostures = await this.configService.getDevicePosturesAll();
        const distinctDevicePostureIds = new Set();
        for (const network of networks) {


            if (!network) {
                this.errorNumber = 1;
                continue;
            }

            if (!network.isEnabled) {
                this.errorNumber = 5;
                continue;
            }


            const rules = await policy.rules.filter(x => x.networkId == network.id);
            for (const rule of rules) {
                if (!rule.isEnabled)
                    continue;
                let f1 = await this.isUserIdOrGroupIdAllowed(rule, user);

                if (f1) {
                    if (rule.profile.device?.postures.length) {
                        rule.profile.device.postures.forEach(x => distinctDevicePostureIds.add(x));
                    }

                }
            }
        }
        const filtered = devicePostures.filter(x => distinctDevicePostureIds.has(x.id));
        const distinctListTmp = new Set();
        for (const item of filtered) {
            if (item.filePathList) {
                item.filePathList.forEach(x => {
                    const key = `/${item.os}/file/${x.path}`;
                    if (!distinctListTmp.has(key)) {
                        result.push({ os: item.os, file: { path: x.path } })
                        distinctListTmp.add(key);
                    }
                })
            }
            if (item.registryList) {
                item.registryList.forEach(x => {
                    const key = `/${item.os}/registry/${x.path}/${x.key}`;
                    if (!distinctListTmp.has(key)) {
                        result.push({ os: item.os, registry: { path: x.path, key: x.key } })
                        distinctListTmp.add(key);
                    }
                })
            }

            if (item.processList) {
                item.processList.forEach(x => {
                    const key = `/${item.os}/process/${x.path}`;
                    if (!distinctListTmp.has(key)) {
                        result.push({ os: item.os, process: { path: x.path } })
                        distinctListTmp.add(key);
                    }
                })
            }
        }

        return result;
    }



    authorizeErrorNumber = PolicyAuthzErrors.NoError;
    /**
     * @summary calculate policy if this tunnel user, can use this service
     * @param tunnel which tunnel
     * @param serviceId to which service
     * @param throwError dont throw errors use c style error return
     * @returns 
     */
    async authorize(tunnel: Tunnel, serviceId: string, throwError: boolean = true): Promise<PolicyAuthzResult> {


        this.authorizeErrorNumber = PolicyAuthzErrors.NoError;
        if (!tunnel) {

            this.authorizeErrorNumber = PolicyAuthzErrors.TunnelNotFound;
            if (!throwError) return { error: this.authorizeErrorNumber };
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrTunnelNotFoundOrNotValid, 'tunnel found');
        }
        logger.debug(`policy authz calculate trackId: ${tunnel.trackId} serviceId:${serviceId}`);


        if (!tunnel.id || !tunnel.clientIp || !tunnel.gatewayId || !tunnel.trackId) {
            this.authorizeErrorNumber = PolicyAuthzErrors.TunnelNotValid;

            if (!throwError) return { error: this.authorizeErrorNumber };
            throw new RestfullException(401, ErrorCodes.ErrTunnelFailed, ErrorCodesInternal.ErrTunnelNotFoundOrNotValid, 'secure tunnel failed');
        }
        const user = await this.configService.getUserById(tunnel.userId || '')
        if (!user) {

            this.authorizeErrorNumber = PolicyAuthzErrors.UserNotFound;
            if (!throwError) return { error: this.authorizeErrorNumber };
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrUserNotFound, 'not found');
        }
        try {
            await HelperService.isValidUser(user);
        } catch (err) {
            this.authorizeErrorNumber = PolicyAuthzErrors.UserNotValid;

            if (!throwError) return { error: this.authorizeErrorNumber };
            throw err;
        }


        const service = await this.configService.getService(serviceId);
        if (!service) {
            this.authorizeErrorNumber = PolicyAuthzErrors.ServiceNotFound;

            if (!throwError) return { error: this.authorizeErrorNumber };
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrServiceNotFound, 'no service');
        }
        if (!service.isEnabled) {
            this.authorizeErrorNumber = PolicyAuthzErrors.ServiceNotValid;

            if (!throwError) return { error: this.authorizeErrorNumber };
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrServiceNotValid, 'service is not enabled');
        }


        const network = await this.configService.getNetwork(service.networkId);
        if (!network) {
            this.authorizeErrorNumber = PolicyAuthzErrors.NetworkNotFound;

            if (!throwError) return { error: this.authorizeErrorNumber };
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrNetworkNotFound, 'no network');
        }

        if (!network.isEnabled) {
            this.authorizeErrorNumber = PolicyAuthzErrors.NetworkNotValid;

            if (!throwError) return { error: this.authorizeErrorNumber };
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrNetworkNotValid, 'no network');
        }

        const gateway = await this.configService.getGateway(tunnel.gatewayId);
        if (!gateway) {
            this.authorizeErrorNumber = PolicyAuthzErrors.GatewayNotFound;

            if (!throwError) return { error: this.authorizeErrorNumber };
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrNetworkNotFound, 'no gateway');
        }

        if (!gateway.isEnabled) {
            this.authorizeErrorNumber = PolicyAuthzErrors.GatewayNotValid;

            if (!throwError) return { error: this.authorizeErrorNumber };
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrNetworkNotValid, 'no gateway');
        }

        const policy = await this.configService.getAuthorizationPolicy();
        const rules = await policy.rules.filter(x => x.serviceId == service.id);

        for (let i = 0; i < rules.length; ++i) {
            let rule = rules[i];
            if (!rule.isEnabled)
                continue;

            let f1 = await this.isUserIdOrGroupIdAllowed(rule, user);
            let f2 = await this.is2FA(rule, tunnel.is2FA || false);
            if (f1 && f2) {

                logger.debug(`policy authz calculate trackId: ${tunnel.trackId} serviceId:${serviceId} rule matched: ${rule.id}`);
                return { error: 0, index: i, rule: rule };
            }

        }
        //no rule match
        this.authorizeErrorNumber = PolicyAuthzErrors.NoRuleMatch;


        if (!throwError) return { error: this.authorizeErrorNumber };
        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrNoRuleMatch, 'not authenticated');


    }

}

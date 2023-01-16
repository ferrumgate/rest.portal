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


export interface UserNetworkListResponse {
    network: Network,
    action: 'deny' | 'allow',
    needs2FA?: boolean,
    needsIp?: boolean,
    needsGateway?: boolean;

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
    RuleDenyMatch = 10,
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
    constructor(private configService: ConfigService,
    ) {


    }

    async checkUserIdOrGroupId(rule: AuthenticationRule | AuthorizationRule, user: User) {
        if (!rule.userOrgroupIds.length) return true;

        if (rule.userOrgroupIds.includes(user.id))
            return true;
        if (rule.userOrgroupIds.find(x => user.groupIds.includes(x)))
            return true;

        return false;

    }
    async check2FA(rule: AuthenticationRule | AuthorizationRule, checkValue: boolean) {
        if (!rule.profile.is2FA) return true
        else
            if (checkValue) return true;
            else
                return false;

    }
    async checkIps(rule: AuthenticationRule, clientIp: string) {
        if (!rule.profile.ips?.length) return true;
        const client = ip.createAddress(clientIp);
        for (const ipprofile of rule.profile.ips) {

            if (client.isInSubnet(ip.createAddress(ipprofile.ip)))
                return true;
        }
        return false;

    }
    errorNumber = PolicyAuthnErrors.NoError;
    /**
     * @summary check user can create a tunnel, check ips, etc...
     * @param user 
     * @param is2FAValidated user logined with 2FA
     * @param tunnel 
     * @returns 
     */
    async authenticate(user: User, is2FAValidated: boolean, tunnel: Tunnel | undefined) {
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
        const policy = await this.configService.getAuthenticationPolicy();
        const rules = await policy.rules.filter(x => x.networkId == network.id);
        for (const rule of rules) {
            if (!rule.isEnabled)
                continue;
            let f1 = await this.checkUserIdOrGroupId(rule, user);
            let f2 = await this.check2FA(rule, is2FAValidated);
            let f3 = await this.checkIps(rule, tunnel.clientIp);
            if (f1 && f2 && f3) {
                if (rule.action == 'allow') {
                    return rule;
                }
                else {
                    this.errorNumber = PolicyAuthnErrors.RuleDenyMatch;
                    throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrRuleDenyMatch, 'not authenticated');
                }

            }

        }
        //no rule match
        this.errorNumber = PolicyAuthnErrors.NoRuleMatch;

        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrNoRuleMatch, 'not authenticated');
    }

    /**
     * @summary find networks that user can connect or why not connect
     * @returns 
     */
    async userNetworks(user: User, is2FAValidated: boolean, clientIp: string) {

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
                let f1 = await this.checkUserIdOrGroupId(rule, user);
                let f2 = await this.check2FA(rule, is2FAValidated);
                let f3 = await this.checkIps(rule, clientIp);
                if (f1 && f2 && f3) {
                    if (rule.action == 'allow') {
                        const gateways = await this.configService.getGatewaysByNetworkId(network.id);
                        if (!gateways.find(x => x.isEnabled)) {
                            result.push({ network: network, action: 'deny', needsGateway: true });
                        } else
                            result.push({ network: network, action: 'allow', })
                        break
                    }
                    else {
                        break
                    }
                } else if (f1) {
                    result.push({ network: network, action: 'deny', needs2FA: !f2, needsIp: !f3 });
                    break;
                }
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

            let f1 = await this.checkUserIdOrGroupId(rule, user);
            let f2 = await this.check2FA(rule, tunnel.is2FA || false);
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

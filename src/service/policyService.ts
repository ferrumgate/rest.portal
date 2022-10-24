import { ErrorCodes, RestfullException } from "../restfullException";
import { User } from "../model/user";
import { ConfigService } from "./configService";
import { TunnelService } from "./tunnelService";
import { AuditService } from "./auditService";
import { RedisService } from "./redisService";
import { Tunnel } from "../model/tunnel";
import { AuthenticationRule } from "../model/authenticationPolicy";
import { AuthorizationRule } from "../model/authorizationPolicy";
import ip from 'ip-cidr';
import { HelperService } from "./helperService";
import { throws } from "assert";


export class PolicyService {
    /**
     *
     */
    constructor(private configService: ConfigService,
        private tunnelService: TunnelService,
        private auditService: AuditService) {


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
    authenticateErrorNumber = 0;

    async authenticate(user: User, is2FAValidated: boolean, tunnelKey: string) {
        //get tunnel basic information
        this.authenticateErrorNumber = 0;
        const tunnel = await this.tunnelService.getTunnel(tunnelKey);
        if (!tunnel || !tunnel.id || !tunnel.clientIp || !tunnel.hostId) {
            this.authenticateErrorNumber = 1;
            //todo activity
            throw new RestfullException(401, ErrorCodes.ErrSecureTunnelFailed, 'secure tunnel failed');
        }

        const gateway = await this.configService.getGateway(tunnel.hostId);
        if (!gateway) {
            this.authenticateErrorNumber = 2;
            //todo activity
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, 'no gateway');
        }
        if (!gateway.isEnabled) {
            this.authenticateErrorNumber = 3;
            //todo activity
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, 'no gateway');
        }
        const network = await this.configService.getNetwork(gateway.networkId || '');
        if (!network) {
            this.authenticateErrorNumber = 4;
            //todo activity
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, 'no network');
        }

        if (!network.isEnabled) {
            this.authenticateErrorNumber = 5;
            //todo activity
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, 'no network');
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
                    //todo activity that this rule matched
                    return;
                }
                else {
                    this.authenticateErrorNumber = 10;
                    //todo activiy 
                    throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not authenticated');
                }

            }

        }
        //no rule match
        this.authenticateErrorNumber = 100;

        //todo activity
        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not authenticated');


    }

    authorizeErrorNumber = 0;
    async authorize(client: string, serviceId: string) {
        this.authorizeErrorNumber = 0;
        const tunnelKey = await this.tunnelService.getTunnelKey(client);
        if (!tunnelKey) {
            //todo activity
            this.authorizeErrorNumber = 1;
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'key not found');
        }
        const tunnel = await this.tunnelService.getTunnel(tunnelKey);
        if (!tunnel) {
            //todo activity
            this.authorizeErrorNumber = 2;
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'tunnel found');
        }


        if (!tunnel || !tunnel.id || !tunnel.clientIp || !tunnel.hostId) {
            this.authorizeErrorNumber = 3;
            //todo activity
            throw new RestfullException(401, ErrorCodes.ErrSecureTunnelFailed, 'secure tunnel failed');
        }
        const user = await this.configService.getUserById(tunnel.userId || '')
        if (!user) {
            //todo activitiy  
            this.authorizeErrorNumber = 4;
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not found');
        }
        try {
            await HelperService.isValidUser(user);
        } catch (err) {
            this.authorizeErrorNumber = 4;
            //todo activitity
            throw err;
        }


        const service = await this.configService.getService(serviceId);
        if (!service) {
            this.authorizeErrorNumber = 5;
            //todo activity
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, 'no service');
        }
        if (!service.isEnabled) {
            this.authorizeErrorNumber = 6;
            //todo activity
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, 'service is not enabled');
        }


        const network = await this.configService.getNetwork(service.networkId);
        if (!network) {
            this.authorizeErrorNumber = 7;
            //todo activity
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, 'no network');
        }

        if (!network.isEnabled) {
            this.authorizeErrorNumber = 8;
            //todo activity
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, 'no network');
        }
        const policy = await this.configService.getAuthorizationPolicy();
        const rules = await policy.rules.filter(x => x.serviceId == service.id);
        for (const rule of rules) {
            if (!rule.isEnabled)
                continue;

            let f1 = await this.checkUserIdOrGroupId(rule, user);
            let f2 = await this.check2FA(rule, tunnel.is2FA || false);
            if (f1 && f2) {

                //todo activity that this rule matched
                return;
            }

        }
        //no rule match
        this.authorizeErrorNumber = 100;

        //todo activity
        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not authenticated');




    }


}
import ip from 'ip-cidr';
import semvr from 'semver';
import { logger } from "../common";
import { AuthSession } from "../model/authSession";
import { AuthenticationRule } from "../model/authenticationPolicy";
import { DevicePosture, OSType } from "../model/authenticationProfile";
import { AuthorizationRule } from "../model/authorizationPolicy";
import { ClientDevicePosture } from "../model/device";
import { Network } from "../model/network";
import { Tunnel } from "../model/tunnel";
import { User } from "../model/user";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { Util } from "../util";
import { ConfigService } from "./configService";
import { HelperService } from "./helperService";
import { IpIntelligenceService } from "./ipIntelligenceService";


export interface UserNetworkListResponse {
    network: Network,
    action: 'deny' | 'allow',
    needs2FA?: boolean,
    needsIp?: boolean,
    whyNeedsIp?: string;
    needsGateway?: boolean;
    needsTime?: boolean;
    needsDevicePosture?: boolean;
    whyNeedsDevicePosture?: string;

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
    DevicePostureNotFound,
    IpIntelligenceCustomBlackListContains,
    IpIntelligenceBlackListContains,
    IpIntelligenceBlackIp,
    DevicePostureOsTypeNotAllowed,
    DevicePostureClientVersionNotAllowed,
    DevicePostureFirewallNotAllowed,
    DevicePostureAntivirusNotAllowed,
    DevicePostureDiscEncryptedNotAllowed,
    DevicePostureMacNotAllowed,
    DevicePostureSerialNotAllowed,
    DevicePosturePostureFileNotAllowed,
    DevicePostureRegistryNotAllowed,
    DevicePostureProcessNotAllowed,

    NoRuleMatch = 100,

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
        let ip = Util.parseIpPort(clientIp).ip || '0.1.0.1';//ip can be like 1.2.3.4#34233 ip#port or [:::]:123
        //check white lists
        if (await this.isCustomWhiteListContains(rule, ip))
            return { result: true };
        // check ip intelligence lists
        if (await this.isIpIntelligenceWhiteListContains(rule, ip))
            return { result: true };

        //check black lists
        if (await this.isCustomBlackListContains(rule, ip))
            return { result: false, errorNumber: PolicyAuthnErrors.IpIntelligenceCustomBlackListContains, error: ErrorCodesInternal.ErrIpIntelligenceCustomBlackListContains };
        // check ip intelligence lists
        if (await this.isIpIntelligenceBlackListContains(rule, ip))
            return { result: false, errorNumber: PolicyAuthnErrors.IpIntelligenceBlackListContains, error: ErrorCodesInternal.ErrIpIntelligenceBlackListContains };;


        //check proxy ip
        if (await this.isIpIntelligenceBlackIp(rule, session))
            return { result: false, errorNumber: PolicyAuthnErrors.IpIntelligenceBlackIp, error: ErrorCodesInternal.ErrIpIntelligenceBlackIp };;

        //check country
        if (await this.isIpIntelligenceCountryContains(rule, session.countryCode))
            return { result: true };

        return { result: false };
    }


    // device posture checks


    async isDevicePostureClientVersionAllowed(clientDp: ClientDevicePosture, dp: DevicePosture) {
        //no rule
        if (!dp.clientVersions?.length) return true;
        const dpVersion = dp.clientVersions[0].version;
        if (!dpVersion) return true;

        //client dont have version info, but rule has
        const clientVersion = clientDp.clientVersion;
        if (!clientVersion) return false;
        if (!semvr.valid(clientVersion) || !semvr.valid(dpVersion)) return false;
        if (semvr.gte(clientVersion, dpVersion))
            return true;


        return false;


    }
    async isDevicePostureFirewallAllowed(clientDp: ClientDevicePosture, dp: DevicePosture) {
        if (!dp.firewallList?.length) return true;
        const dpNeedsFirewall = true;
        if (clientDp.platform == 'linux') return true;
        if (!clientDp.firewalls?.length) return false;
        const clientFirewallStatus = clientDp.firewalls[0].isEnabled;

        if (clientFirewallStatus) return true;
        return false;

    }
    async isDevicePostureAntivirusAllowed(clientDp: ClientDevicePosture, dp: DevicePosture) {
        if (!dp.antivirusList?.length) return true;
        const dpNeedsAntivirus = true;
        if (clientDp.platform == 'linux') return true;
        if (!clientDp.antiviruses?.length) return false;
        const clientAntivirusStatus = clientDp.antiviruses[0].isEnabled;

        if (clientAntivirusStatus) return true;
        return false;

    }
    async isDevicePostureDiscEncryptedAllowed(clientDp: ClientDevicePosture, dp: DevicePosture) {
        if (!dp.discEncryption) return true;
        if (!clientDp.encryptedDiscs?.length) return false;

        const clientEncryptedDiscsStatus = clientDp.encryptedDiscs[0].isEncrypted;
        if (clientEncryptedDiscsStatus) return true;
        return false;

    }
    async isDevicePostureMacAllowed(clientDp: ClientDevicePosture, dp: DevicePosture) {
        //all macs
        if (!dp.macList?.length) return true;

        if (!clientDp.macs?.length) return false;

        if (dp.macList.some(x => clientDp.macs.map(y => y.toLowerCase()).some(y => y.trim() == x.value.toLowerCase().trim()))) return true;
        return false;

    }
    async isDevicePostureSerialAllowed(clientDp: ClientDevicePosture, dp: DevicePosture) {
        //all macs
        if (!dp.serialList?.length) return true;

        if (!clientDp.serial?.value) return false;

        if (dp.serialList.some(x => clientDp.serial.value.trim() == x.value.trim())) return true;
        return false;

    }

    async isDevicePostureFileAllowed(clientDp: ClientDevicePosture, dp: DevicePosture) {
        //all macs
        if (!dp.filePathList?.length) return true;

        if (!clientDp.files?.length) return false;
        let founded = 0;
        for (const file of dp.filePathList) {
            for (const cfile of clientDp.files) {
                if (cfile.path.toLowerCase().includes(file.path.toLowerCase())) {
                    if (!file.sha256) {
                        founded++
                        break;
                    }
                    else
                        if (cfile.sha256 == file.sha256) {
                            founded++;
                            break;
                        }
                }
            }
        }
        //if all items founded
        if (founded >= dp.filePathList.length) return true;
        return false;

    }

    async isDevicePostureProcessAllowed(clientDp: ClientDevicePosture, dp: DevicePosture) {
        //all macs
        if (!dp.processList?.length) return true;

        if (!clientDp.processes?.length) return false;
        let founded = 0;
        for (const file of dp.processList) {
            for (const cfile of clientDp.processes) {
                if (cfile.path.toLowerCase().includes(file.path.toLowerCase())) {
                    if (!file.sha256) {
                        founded++
                        break;
                    }
                    else
                        if (cfile.sha256 == file.sha256) {
                            founded++;
                            break;
                        }
                }
            }
        }
        //if all items founded
        if (founded >= dp.processList.length) return true;
        return false;

    }

    async isDevicePostureRegistryAllowed(clientDp: ClientDevicePosture, dp: DevicePosture) {
        //all macs
        if (!dp.registryList?.length) return true;
        if (clientDp.platform != 'win32') return true;

        if (!clientDp.registries?.length) return false;
        let founded = 0;
        for (const file of dp.registryList) {
            for (const cfile of clientDp.registries) {
                if (cfile.path == file.path && cfile.key == file.key) {
                    founded++;
                    break;
                }
            }
        }
        //if all items founded
        if (founded >= dp.registryList.length) return true;
        return false;

    }
    async isDevicePostureOsVersionAllowed(clientDp: ClientDevicePosture, dp: DevicePosture) {

        if (!dp.osVersions?.length) return true;
        if (!clientDp.os?.version) return false;
        return dp.osVersions.filter(x => x.release).some(x => semvr.satisfies(clientDp.os.version, '>= ' + x.release));

    }




    async isDevicePostureAllowed(rule: AuthenticationRule, session: AuthSession, devicePostures?: DevicePosture[], clientDp?: ClientDevicePosture,) {

        // no rule, allowed
        if (!rule.profile?.device) return { result: true }
        if (!rule.profile.device?.postures.length) return { result: true };
        // no target list, allowed
        if (!devicePostures || !devicePostures.length) return { result: true }

        //lookup list
        const filteredDevicePostures = devicePostures.filter(x => x.isEnabled).filter(x => rule.profile.device?.postures.includes(x.id));
        // no target list, allowed
        if (!filteredDevicePostures.length) return { result: true }


        // no rule found, denied
        if (!clientDp) return { result: false, errorNumber: PolicyAuthnErrors.DevicePostureNotFound, error: ErrorCodesInternal.ErrDevicePostureNotFound };

        let follow = { errorNumber: PolicyAuthnErrors.NoError, error: '' }

        for (const dp of filteredDevicePostures) {
            if (dp.os != clientDp.platform) {
                //follow = { errorNumber: PolicyAuthnErrors.DevicePostureOsTypeNotAllowed, error: ErrorCodesInternal.ErrDevicePostureOsTypeNotAllowed }
                continue;
            }
            if (!await this.isDevicePostureOsVersionAllowed(clientDp, dp)) {
                follow = { errorNumber: PolicyAuthnErrors.DevicePostureOsTypeNotAllowed, error: ErrorCodesInternal.ErrDevicePostureClientVersionNotAllowed }
                continue;
            }
            if (!await this.isDevicePostureClientVersionAllowed(clientDp, dp)) {
                follow = { errorNumber: PolicyAuthnErrors.DevicePostureClientVersionNotAllowed, error: ErrorCodesInternal.ErrDevicePostureClientVersionNotAllowed }
                continue;
            }
            if (!await this.isDevicePostureFirewallAllowed(clientDp, dp)) {
                follow = { errorNumber: PolicyAuthnErrors.DevicePostureFirewallNotAllowed, error: ErrorCodesInternal.ErrDevicePostureFirewallNotAllowed }
                continue;
            }
            if (!await this.isDevicePostureAntivirusAllowed(clientDp, dp)) {
                follow = { errorNumber: PolicyAuthnErrors.DevicePostureAntivirusNotAllowed, error: ErrorCodesInternal.ErrDevicePostureAntivirusNotAllowed }
                continue;
            }
            if (!await this.isDevicePostureDiscEncryptedAllowed(clientDp, dp)) {
                follow = { errorNumber: PolicyAuthnErrors.DevicePostureDiscEncryptedNotAllowed, error: ErrorCodesInternal.ErrDevicePostureDiscEncryptedNotAllowed }
                continue;
            }
            if (!await this.isDevicePostureMacAllowed(clientDp, dp)) {

                follow = { errorNumber: PolicyAuthnErrors.DevicePostureMacNotAllowed, error: ErrorCodesInternal.ErrDevicePostureMacNotAllowed }
                continue;
            }
            if (!await this.isDevicePostureSerialAllowed(clientDp, dp)) {
                follow = { errorNumber: PolicyAuthnErrors.DevicePostureSerialNotAllowed, error: ErrorCodesInternal.ErrDevicePostureSerialNotAllowed }
                continue;
            }
            if (!await this.isDevicePostureFileAllowed(clientDp, dp)) {
                follow = { errorNumber: PolicyAuthnErrors.DevicePosturePostureFileNotAllowed, error: ErrorCodesInternal.ErrDevicePostureFileNotAllowed }
                continue;
            }
            if (!await this.isDevicePostureRegistryAllowed(clientDp, dp)) {
                follow = { errorNumber: PolicyAuthnErrors.DevicePostureRegistryNotAllowed, error: ErrorCodesInternal.ErrDevicePostureRegisryNotAllowed }
                continue;
            }
            if (!await this.isDevicePostureProcessAllowed(clientDp, dp)) {
                follow = { errorNumber: PolicyAuthnErrors.DevicePostureProcessNotAllowed, error: ErrorCodesInternal.ErrDevicePostureProcessNotAllowed }
                continue;
            }

            return { result: true };


        }

        //no rule matched

        return {
            result: false,
            errorNumber: follow.error ? follow.errorNumber : PolicyAuthnErrors.DevicePostureOsTypeNotAllowed,
            error: follow.error ? follow.error : ErrorCodesInternal.ErrDevicePostureOsTypeNotAllowed
        };



    }




    errorNumber = PolicyAuthnErrors.NoError;
    /**
     * @summary check user can create a tunnel, check ips, etc...
     * @returns 
     */
    async authenticate(user: User, session: AuthSession | undefined, tunnel: Tunnel | undefined, clientDp: ClientDevicePosture | undefined) {
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
        const devicePostures = await this.configService.getDevicePosturesAll();
        const policy = await this.configService.getAuthenticationPolicy();
        const rules = await policy.rules.filter(x => x.networkId == network.id);
        for (const rule of rules) {
            if (!rule.isEnabled)
                continue;
            let f1 = await this.isUserIdOrGroupIdAllowed(rule, user);
            let f2 = await this.is2FA(rule, is2FAValidated);
            let f3 = await this.isIpIntelligenceAllowed(rule, session, tunnel.clientIp);
            let f4 = await this.isTimeAllowed(rule);
            let f5 = await this.isDevicePostureAllowed(rule, session, devicePostures, clientDp);


            if (f1 && f2 && f3.result && f4 && f5.result) {

                return rule;

            }
            //for better visibility
            if (f1) {
                logger.warn(`user not authenticated f2:${f2} f3:${JSON.stringify(f3)} f4:${f4} f5:${JSON.stringify(f5)}`)
                if (!f2)
                    error = ErrorCodesInternal.ErrNo2FAMatch;
                else
                    if (!f3.result) {
                        if (f3.errorNumber)
                            this.errorNumber = f3.errorNumber;
                        if (f3.error) {
                            error = f3.error;
                        }
                        else
                            error = ErrorCodesInternal.ErrNoLocationMatch;
                    }
                    else if (!f4)
                        error = ErrorCodesInternal.ErrNoTimeMatch;
                    else
                        if (!f5.result) {
                            if (f5.errorNumber)
                                this.errorNumber = f5.errorNumber;
                            if (f5.error)
                                error = f5.error;
                        } else
                            error = ErrorCodesInternal.ErrNoDevicePostureMatch;

            }

        }
        //no rule match
        //error not set before, set it no match
        if (this.errorNumber == PolicyAuthnErrors.NoError)
            this.errorNumber = PolicyAuthnErrors.NoRuleMatch;
        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, error, 'not authenticated');
    }

    /**
     * @summary find networks that user can connect or why not connect
     * @returns 
     */
    async userNetworks(user: User, session: AuthSession, clientIp: string, cliendDP?: ClientDevicePosture) {

        this.errorNumber = 0;
        let result: UserNetworkListResponse[] = [];
        let resultMap: Map<string, UserNetworkListResponse> = new Map();
        const networks = await this.configService.getNetworksAll();
        const devicePostures = await this.configService.getDevicePosturesAll();
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
                let f5 = await this.isDevicePostureAllowed(rule, session, devicePostures, cliendDP);

                if (f1 && f2 && f3.result && f4 && f5.result) {

                    const gateways = await this.configService.getGatewaysByNetworkId(network.id);
                    if (!gateways.find(x => x.isEnabled)) {
                        result.push({ network: network, action: 'deny', needsGateway: true });
                    } else {
                        result.push({ network: network, action: 'allow', })
                    }
                    resultMap.set(network.id, result[result.length - 1]);// if allowed ok
                    break;


                } else if (f1) {
                    result.push(
                        {
                            network: network,
                            action: 'deny',
                            needs2FA: !f2,
                            needsIp: !f3.result,
                            whyNeedsIp: f3.error,
                            needsTime: !f4,
                            needsDevicePosture: !f5.result,
                            whyNeedsDevicePosture: f5.error
                        });
                    resultMap.set(network.id, result[result.length - 1]);// if deny, set last deny
                    //break; dont break
                }
            }
        }

        return Array.from(resultMap.values());


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

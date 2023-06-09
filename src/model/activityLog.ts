export const ActivityStatus = {
    Success: 200,
    AuthenticationFailed: 1,
}
export interface ActivityLog {
    insertDate: string;
    requestId: string;
    type: string;//'login try','login allow','login deny','service allow','service deny','pam activated'
    authSource: string;//google, apikey
    ip: string;
    status: number;//200 success;
    statusMessage?: string;
    statusMessageDetail?: string;


    username?: string;
    userId?: string;
    user2FA?: boolean;

    requestPath?: string;
    sessionId?: string;
    is2FA?: boolean;
    trackId?: number;
    assignedIp?: string;
    tunnelId?: string;
    serviceId?: string;
    serviceName?: string;
    serviceProtocol?: string;
    networkId?: string;
    networkName?: string;
    gatewayId?: string;
    gatewayName?: string;
    tun?: string;
    tunType?: string;
    authnRuleId?: string
    authnRuleName?: string;
    authzRuleId?: string;
    authzRuleName?: string;

    deviceId?: string;
    deviceName?: string;
    osName?: string;
    osVersion?: string;
    browser?: string;
    browserVersion?: string;

    sourceIp?: string;
    sourcePort?: number;
    destinationIp?: string;
    destinationPort?: number;
    networkProtocol?: string;

    countryCode?: string;
    countryName?: string;
    isProxyIp?: boolean;
    isHostingIp?: boolean;
    isCrawlerIp?: boolean;
    //dns related fields
    dnsQueryType?: string;
    dnsQuery?: string;
    dnsStatus?: string;
    dnsFqdnCategoryId?: string;
    dnsFqdnCategoryName?: string;

}
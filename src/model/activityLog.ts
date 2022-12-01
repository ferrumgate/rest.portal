export const ActivitiyStatus = {
    Success: 200,
    AuthenticationFailed: 1,
}
export interface ActivityLog {
    insertDate: string;
    requestId: string;
    type: string;//'login try','login success','login deny','service success','service deny','pam activated'
    authSource: string;//google, apikey
    ip: string;
    status: number;//200 success;
    statusMessage?: string;
    statusMessage2?: string;

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
    networkId?: string;
    networkName?: string;
    gatewayId?: string;
    gatewayName?: string;
    tun?: string;
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
}
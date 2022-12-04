
export interface SummaryConfig {
    networkCount: number;
    gatewayCount: number;
    userCount: number;
    groupCount: number;
    serviceCount: number;
    authnCount: number;
    authzCount: number
}

export interface SummaryActive {
    sessionCount: number;
    tunnelCount: number;
}
export interface AuthSession {
    id: string;
    userId: string;
    username: string;
    ip: string;
    insertDate: string;
    lastSeen: string;
    is2FA: boolean;
    //isPAM: boolean;
    source: string;
    countryCode?: string;
    countryName?: string;
    isProxyIp?: boolean;
    isHostingIp?: boolean;
    isCrawlerIp?: boolean;
}
/**
 * @summary tunnel session
 * when a tunnel is created, also this data is created
 */
export interface Tunnel {
    // a unique 64 byte random string
    id?: string;
    // assigned interface name
    tun?: string;
    //connected client id
    clientIp?: string;
    // peer client ip
    assignedClientIp?: string;
    // track id
    trackId?: number;
    // authenticated user id
    userId?: string;
    // authentication time
    authenticatedTime?: string;
    // gateway id
    gatewayId?: string
    // service network
    serviceNetwork?: string;
    // is2FA used
    is2FA?: boolean;
    /*  */
    //belongs sessionId
    sessionId?: string;
}
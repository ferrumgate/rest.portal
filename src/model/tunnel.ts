/**
 * @summary tunnel session
 * when a tunnel is created, also this data is created
 */
export interface Tunnel {
    // a unique 64 byte random string
    id?: string;
    // assigned interface name
    tun?: string;
    /**
     * @summary connected client ip and port like 1.2.3.4#34343    
     */
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

    //tunnel type
    type?: string;
}
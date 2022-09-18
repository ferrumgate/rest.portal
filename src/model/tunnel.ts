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
    // authenticated user id
    userId?: string;
    // authentication time
    authenticatedTime?: string;
    // host id
    hostId?: string
    // service network
    serviceNetwork?: string;
}
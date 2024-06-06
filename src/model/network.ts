/**
 * a machine that can connect to a internal network
 */
export interface Gateway {
    id: string;
    name: string;
    labels: string[];
    networkId?: string;
    nodeId?: string;
    isEnabled?: boolean;
    insertDate: string;
    updateDate: string;
}

export interface GatewayDetail {
    id: string;
    nodeId: string,
    arch?: string;
    cpusCount?: number,
    cpuInfo?: string,
    hostname?: string,
    totalMem: number,
    type: string,
    uptime?: number,
    version: string,
    platform: string,
    release: string,
    freeMem: number,
    interfaces: string,
    lastSeen: number
}


/**
 * @summary a group of @see Gateway s
 */
export interface Network {
    id: string;
    name: string;
    labels: string[];
    clientNetwork: string;
    serviceNetwork: string;
    insertDate: string;
    updateDate: string;
    isEnabled?: boolean;

    /**
     * @summary ssh tunnel connection public ip and port
     * @example ssh.ferrumgate.com:9999
     */
    sshHost?: string;
    /*  openVpnHost?: string;
     wireguardHost?: string; */



}

/***
 * @summary clone only needed parameters
 */
export function cloneNetwork(net: Network): Network {
    return {
        id: net.id, clientNetwork: net.clientNetwork, labels: net.labels,
        name: net.name, serviceNetwork: net.serviceNetwork, insertDate: net.insertDate, updateDate: net.updateDate,
        isEnabled: net.isEnabled, sshHost: net.sshHost,
        /* openVpnHost: net.openVpnHost, wireguardHost: net.wireguardHost */


    }
}

/**
 * @summary cppy only needed parameters
 * @param gate 
 * @returns 
 */
export function cloneGateway(gate: Gateway): Gateway {
    return {
        id: gate.id, labels: gate.labels, name: gate.name,
        networkId: gate.networkId, isEnabled: gate.isEnabled,
        insertDate: gate.insertDate, updateDate: gate.updateDate,
        nodeId: gate.nodeId
    }
}


/**
 * a machine that is a part of ferrumgate cluster
 */
export interface Node {
    id: string;
    name: string;
    labels: string[];
    insertDate: string;
    updateDate: string;
}
/**
 * Host details like network, cpu
 */
export interface NodeDetail {
    id: string;
    arch?: string;
    cpusCount?: number,
    cpuInfo?: string,
    hostname?: string,
    totalMem: number,
    type: string,
    uptime?: number,
    version: string,
    platform: string,
    release: string,
    freeMem: number,
    interfaces: string,
    lastSeen: number,
    roles?: string;
    nodeIp?: string,
    nodePort?: string,
    nodeIpw?: string,
    nodePortw?: string,
    nodePublicKey?: string,
    redisPass?: string,
    redisIntelPass?: string,
    esUser?: string,
    esPass?: string,
    esIntelUser?: string,
    esIntelPass?: string,
    encryptKey?: string,
    ferrumCloudId?: string,
    ferrumCloudUrl?: string,
    ferrumCloudToken?: string,


}


/**
 * @summary cppy only needed parameters
 * @param host
 * @returns 
 */
export function cloneNode(host: Node): Node {
    return {
        id: host.id, labels: host.labels, name: host.name,
        insertDate: host.insertDate, updateDate: host.updateDate
    }
}
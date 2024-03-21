
export interface ServicePort {
    port: number;
    isTcp?: boolean;
    isUdp?: boolean;
    protocol?: string;
    [key: string]: any;

}
export interface ServiceHost {
    host: string;
    [key: string]: any;

}
export interface ServiceAlias {
    host: string;
}


/**
 * private network service definition like
 * mysql on a machine
 */
export interface Service {
    id: string;
    name: string;
    labels?: string[];
    //listen ports
    ports: ServicePort[];
    protocol?: 'dns' | 'raw' | string;
    //upstream hosts and rules
    hosts: ServiceHost[];
    count: number;
    networkId: string;
    isEnabled: boolean;
    assignedIp: string;
    insertDate: string;
    updateDate: string;
    isSystem?: boolean;
    aliases?: ServiceAlias[];


}


export function cloneService(service: Service): Service {
    return {
        id: service.id,
        name: service.name,
        labels: service.labels,
        ports: Array.from(JSON.parse(JSON.stringify(service.ports))),
        hosts: Array.from(JSON.parse(JSON.stringify(service.hosts))),
        protocol: service.protocol,
        networkId: service.networkId,
        isEnabled: service.isEnabled,
        assignedIp: service.assignedIp,
        insertDate: service.insertDate,
        updateDate: service.updateDate,
        isSystem: service.isSystem,
        count: service.count,
        aliases: Array.from(JSON.parse(JSON.stringify(service.aliases || []))),

    }
}
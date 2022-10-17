/**
 * private network service definition like
 * mysql on a machine
 */
export interface Service {
    id: string;
    name: string;
    labels?: string[];
    tcp?: number;
    udp?: number;
    protocol?: string;
    host: string;
    networkId: string;
    isEnabled: boolean;
    assignedIp: string;
    insertDate: string;
    updateDate: string;

}

export function cloneService(service: Service): Service {
    return {
        id: service.id,
        name: service.name,
        labels: service.labels,
        tcp: service.tcp,
        udp: service.udp,
        protocol: service.protocol,
        networkId: service.networkId,
        isEnabled: service.isEnabled,
        host: service.host,
        assignedIp: service.assignedIp,
        insertDate: service.insertDate,
        updateDate: service.updateDate
    }
}
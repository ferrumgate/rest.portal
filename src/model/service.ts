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
    ips: string[];
    networkIds?: string[];
}

export interface Dns {

    records: DnsRecord[]
}

export interface DnsRecord {
    id: string;
    fqdn: string;
    ip: string;
    labels?: string[];
    insertDate: string;
    updateDate: string;
    isEnabled: boolean;
}

export function cloneDnsRecord(obj: DnsRecord): DnsRecord {
    let item: DnsRecord = {
        id: obj.id, insertDate: obj.insertDate, updateDate: obj.updateDate,
        fqdn: obj.fqdn, labels: obj.labels,
        ip: obj.ip,
        isEnabled: obj.isEnabled
    }

    return item;
}
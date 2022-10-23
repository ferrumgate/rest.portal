export interface Device {
    id: string;
    name: string;
    hostname: string;
    os: string;
    osDetail: string;
    lastSeen: string;
    firstSeen: string;
    macs: string[];
    serials: string[];
    enabled: boolean;
    labels: [];
    insertDate: string;
    updateDate: string;

}

export interface DevicePosture {
    appVersion: string;
}




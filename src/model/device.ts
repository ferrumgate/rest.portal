export interface DeviceLog {
    id: string;
    hostname: string;
    osName: string;
    osVersion: string;
    macs: string;
    serial: string;
    userId: string;
    username: string;
    insertDate: string;
    clientVersion: string;
    clientSha256: string;
    platform: string;
    hasEncryptedDisc: boolean;
    hasFirewall: boolean;
    hasAntivirus: boolean;
    isHealthy: boolean;
    whyNotHealthy?: string;
    networkdId?: string;
    networkName?: string;
}
/// data from client
export interface ClientDevicePosture {
    clientId: string;
    clientVersion: string;
    clientSha256: string;
    hostname: string;
    macs: string[]
    platform: string;
    os: { name: string, version: string };
    registries: { path: string, key?: string, value?: string }[];
    files: { path: string, sha256?: string }[];
    processes: { path: string, sha256?: string }[];
    processSearch: string[];
    memory: { total: number, free: number };
    serial: { value: string };
    encryptedDiscs: { isEncrypted: boolean }[];
    antiviruses: { isEnabled: boolean }[];
    firewalls: { isEnabled: boolean }[];

}




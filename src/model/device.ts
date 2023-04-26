export interface DeviceLog {
    id: string;
    hostname: string;
    osName: string;
    osVersion: string;
    macs: string;
    serial: string;
    insertDate: string;
    clientVersion: string;
    clientSha256: string;
    platform: string;
    hasEncryptedDisc: boolean;
    hasFirewall: boolean;
    hasAntivirus: boolean;
    isHealthy: boolean;
    whyNotHealthy?: string;
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
    registries: { isExists: boolean, path: string, key?: string, value?: string }[];
    files: { isExists: boolean, path: string, sha256?: string }[];
    processes: { name: string }[];
    processSearch: string[];
    memory: { total: number, free: number };
    serial: { serial: string };
    encryptedDiscs: { isEncrypted: boolean }[];
    antiviruses: { isEnabled: boolean }[];
    firewalls: { isEnabled: boolean }[];

}




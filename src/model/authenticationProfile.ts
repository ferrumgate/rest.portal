import { Util } from "../util";

export interface IpProfile {
    ip: string;
}
export function cloneIpProfile(p: IpProfile): IpProfile {
    return {
        ip: p.ip
    }
}

export interface IpIntelligenceProfile {

    whiteLists: string[];
    blackLists: string[];
    isProxy: boolean;
    isHosting: boolean;
    isCrawler: boolean;
}
export function cloneIpIntelligenceProfile(p: IpIntelligenceProfile): IpIntelligenceProfile {
    return {

        blackLists: Array.from(p.blackLists),
        whiteLists: Array.from(p.whiteLists),
        isCrawler: p.isCrawler,
        isHosting: p.isHosting,
        isProxy: p.isProxy
    }
}

export interface TimeProfile {
    timezone: string;
    days: number[],
    startTime?: number
    endTime?: number
}
export function cloneTimeProfile(p: TimeProfile): TimeProfile {
    return {
        timezone: p.timezone,
        days: Array.from(p.days),
        endTime: p.endTime,
        startTime: p.startTime
    }
}
export interface LocationProfile {
    countryCode: string;
}

export function cloneLocationProfile(p: LocationProfile): LocationProfile {
    return {
        countryCode: p.countryCode
    }
}





export interface AppVersion {
    version?: string;
    sha256?: string;
    fingerprint?: string;
}

export type OSType = 'win32' | 'darwin' | 'linux' | 'android' | 'ios';

export interface DevicePosture {
    id: string;
    name: string;
    labels: string[];
    isEnabled: boolean;
    insertDate: string;
    updateDate: string;
    os: OSType;
    osVersions?: { name: string, release?: string }[];
    filePathList?: { path: string; sha256?: string; fingerprint?: string }[];
    processList?: { path: string; sha256?: string; fingerprint?: string }[];
    registryList?: { path: string; key?: string, value?: string; }[];
    hddEncryption?: boolean;
    firewallList?: { name: string }[];
    antivirusList?: { name: string }[];
    macList?: { value: string }[];
}
export function cloneDevicePosture(val: DevicePosture): DevicePosture {
    return {
        id: val.id,
        name: val.name,
        labels: Array.from(val.labels),
        isEnabled: val.isEnabled,
        insertDate: val.insertDate,
        updateDate: val.updateDate,
        os: val.os,
        osVersions: val.osVersions ? Array.from(val.osVersions.map(x => { return { name: x.name, release: x.release } })) : undefined,
        filePathList: val.filePathList ? Array.from(val.filePathList.map(x => { return { path: x.path, sha256: x.sha256, fingerprint: x.fingerprint } })) : undefined,
        processList: val.processList ? Array.from(val.processList.map(x => { return { path: x.path, sha256: x.sha256, fingerprint: x.fingerprint } })) : undefined,
        registryList: val.registryList ? Array.from(val.registryList.map(x => { return { path: x.path, key: x.key, value: x.value } })) : undefined,
        hddEncryption: Util.isUndefinedOrNull(val.hddEncryption) ? undefined : val.hddEncryption,
        firewallList: val.firewallList ? Array.from(val.firewallList.map(x => { return { name: x.name } })) : undefined,
        antivirusList: val.antivirusList ? Array.from(val.antivirusList.map(x => { return { name: x.name } })) : undefined,
        macList: val.macList ? Array.from(val.macList.map(x => { return { value: x.value } })) : undefined,
    };
}


export interface DeviceProfile {
    //devicepostureprofile ids
    postures: string[];
}
export function cloneDeviceProfile(p: DeviceProfile): DeviceProfile {
    return {
        postures: Array.from(p.postures)
    }
}






/**
 * base authentication profile for users
 */
export interface AuthenticationProfile {
    app?: AppVersion;
    is2FA?: boolean;
    //custom white list
    whiteListIps?: IpProfile[];
    blackListIps?: IpProfile[]
    ipIntelligence?: IpIntelligenceProfile;
    times?: TimeProfile[];
    locations?: LocationProfile[];
    device?: DeviceProfile;

}

export function cloneAuthenticatonProfile(pr: AuthenticationProfile): AuthenticationProfile {

    return {
        is2FA: pr.is2FA,
        app: pr.app ? { version: pr.app?.version } : undefined,
        whiteListIps: pr.whiteListIps ? Array.from(pr.whiteListIps.map(x => cloneIpProfile(x))) : undefined,
        blackListIps: pr.blackListIps ? Array.from(pr.blackListIps.map(x => cloneIpProfile(x))) : undefined,
        ipIntelligence: pr.ipIntelligence ? cloneIpIntelligenceProfile(pr.ipIntelligence) : undefined,
        times: pr.times ? Array.from(pr.times.map(x => cloneTimeProfile(x))) : undefined,
        locations: pr.locations ? Array.from(pr.locations.map(x => cloneLocationProfile(x))) : undefined,
        device: pr.device ? cloneDeviceProfile(pr.device) : undefined,
    }
}
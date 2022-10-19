
export interface IpProfile {
    ip: string;
}
export function cloneIpProfile(p: IpProfile): IpProfile {
    return {
        ip: p.ip
    }
}

export interface DayProfile {
    day: number;
    hourStart?: number;
    hourEnd?: number;
}
export function cloneDayProfile(p: DayProfile): DayProfile {
    return {
        day: p.day,
        hourStart: p.hourStart, hourEnd: p.hourEnd
    }
}
export interface LocationProfile {
    loc: string;
}

export function cloneLocationProfile(p: LocationProfile): LocationProfile {
    return {
        loc: p.loc
    }
}


export interface BrowserProfile {
    items: {
        name: string,
        version?: string
    }[];
    includeAll: boolean;
    includeAtLeast: boolean;

}
export function cloneBrowserProfile(val: BrowserProfile): BrowserProfile {
    return {
        items: val?.items ? Array.from(val.items.map(x => { return { name: x.name, version: x.version } })) : [],
        includeAll: val.includeAll, includeAtLeast: val.includeAtLeast

    }
}

export interface ApplicationProfile {
    items: {
        name: string;
        version?: string
    }[];
    includeAll: boolean;
    includeAtLeast: boolean;

}

export function cloneApplicationProfile(val: ApplicationProfile): ApplicationProfile {
    return {
        items: val?.items ? Array.from(val.items.map(x => { return { name: x.name, version: x.version } })) : [],
        includeAll: val.includeAll, includeAtLeast: val.includeAtLeast
    }
}

export interface RegistryProfile {
    items: {
        key: string; value: string;
    }[];
    includeAll: boolean;
    includeAtLeast: boolean;
}
export function cloneRegistryProfile(val: RegistryProfile): RegistryProfile {
    return {
        items: val?.items ? Array.from(val.items.map(x => { return { key: x.key, value: x.value } })) : [],
        includeAll: val.includeAll, includeAtLeast: val.includeAtLeast
    }
}

export interface FileProfile {
    items: {
        path: string;
    }[];
    includeAll: boolean;
    includeAtLeast: boolean;
}
export function cloneFileProfile(val: FileProfile): FileProfile {
    return {
        items: val?.items ? Array.from(val.items.map(x => { return { path: x.path, } })) : [],
        includeAll: val.includeAll, includeAtLeast: val.includeAtLeast
    }
}
export interface FirewallProfile {
    items: {
        name: string;
    }[];
    includeAll: boolean;
    includeAtLeast: boolean;
    any: boolean;

}
export function cloneFirewallProfile(val: FirewallProfile): FirewallProfile {
    return {
        items: val?.items ? Array.from(val.items.map(x => { return { name: x.name } })) : [],
        includeAll: val.includeAll, includeAtLeast: val.includeAtLeast, any: val.any

    }
}
export interface AntivirusProfile {
    items: {
        name: string;
    }[];
    includeAll: boolean;
    includeAtLeast: boolean;
    any: boolean;
}
export function cloneAntivirusProfile(val: AntivirusProfile): AntivirusProfile {
    return {
        items: val?.items ? Array.from(val.items.map(x => { return { name: x.name } })) : [],
        includeAll: val.includeAll, includeAtLeast: val.includeAtLeast, any: val.any
    }
}

export interface DeviceProfile {
    os: string;
    detail?: string;
    version?: string;
    isFingerPrintEnabled?: boolean;
    fileProfile?: FileProfile;
    registryProfile?: RegistryProfile;
    browserProfile?: BrowserProfile;
    applicationProfile?: ApplicationProfile;
    firewallProfile?: FirewallProfile;

}
export function cloneDeviceProfile(val: DeviceProfile): DeviceProfile {
    return {
        os: val.os,
        detail: val.detail,
        version: val.version,
        isFingerPrintEnabled: val.isFingerPrintEnabled,
        fileProfile: val.fileProfile ? cloneFileProfile(val.fileProfile) : undefined,
        registryProfile: val.registryProfile ? cloneRegistryProfile(val.registryProfile) : undefined,
        browserProfile: val.browserProfile ? cloneBrowserProfile(val.browserProfile) : undefined,
        applicationProfile: val.applicationProfile ? cloneApplicationProfile(val.applicationProfile) : undefined,
        firewallProfile: val.firewallProfile ? cloneFirewallProfile(val.firewallProfile) : undefined

    }
}
export interface AppVersion {
    version?: string;
}



/**
 * base authentication profile for users
 */
export interface AuthenticationProfile {
    app?: AppVersion;
    is2FA?: boolean;
    ips?: IpProfile[];
    days?: DayProfile[];
    locations?: LocationProfile[];
    devices?: DeviceProfile[];

}

export function cloneAuthenticatonProfile(pr: AuthenticationProfile): AuthenticationProfile {

    return {
        app: pr.app ? { version: pr.app?.version } : undefined,
        ips: pr.ips ? Array.from(pr.ips.map(x => cloneIpProfile(x))) : undefined,
        days: pr.days ? Array.from(pr.days.map(x => cloneDayProfile(x))) : undefined,
        locations: pr.locations ? Array.from(pr.locations.map(x => cloneLocationProfile(x))) : undefined,
        devices: pr.devices ? Array.from(pr.devices.map(x => cloneDeviceProfile(x))) : undefined
    }
}
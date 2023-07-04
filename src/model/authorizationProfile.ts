export interface FqdnProfile {
    fqdn: string;
}
export function cloneFqdnProfile(p: FqdnProfile): FqdnProfile {
    return {
        fqdn: p.fqdn
    }
}

export interface FqdnIntelligenceProfile {

    ignoreFqdns: FqdnProfile[];
    whiteFqdns: FqdnProfile[];
    blackFqdns: FqdnProfile[];
    ignoreLists: string[];
    whiteLists: string[];
    blackLists: string[];


}
export function cloneFqdnIntelligenceProfile(p: FqdnIntelligenceProfile): FqdnIntelligenceProfile {
    return {
        ignoreFqdns: p.ignoreFqdns ? Array.from(p.ignoreFqdns.map(x => cloneFqdnProfile(x))) : [],
        whiteFqdns: p.whiteFqdns ? Array.from(p.whiteFqdns.map(x => cloneFqdnProfile(x))) : [],
        blackFqdns: p.blackFqdns ? Array.from(p.blackFqdns.map(x => cloneFqdnProfile(x))) : [],
        ignoreLists: p.ignoreLists ? Array.from(p.ignoreLists) : [],
        blackLists: p.blackLists ? Array.from(p.blackLists) : [],
        whiteLists: Array.from(p.whiteLists),
    }
}

export interface AuthorizationProfile {
    is2FA: boolean;
    fqdnIntelligence?: FqdnIntelligenceProfile;

}

export function cloneAuthorizationProfile(val: AuthorizationProfile): AuthorizationProfile {
    return {
        is2FA: val.is2FA,
        fqdnIntelligence: val.fqdnIntelligence ? cloneFqdnIntelligenceProfile(val.fqdnIntelligence) : undefined
    }
}
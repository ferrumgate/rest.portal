/**
 * base security profile for users
 */
export interface SecurityProfile {
    ips?: string[];
    clocks?: string[];
    locations?: string[];
}

export function cloneSecurityProfile(pr?: SecurityProfile): SecurityProfile | undefined {
    if (!pr) return undefined;
    return {
        ips: pr.ips ? Array.from(pr.ips) : undefined,
        clocks: pr.clocks ? Array.from(pr.clocks) : undefined,
        locations: pr.locations ? Array.from(pr.locations) : undefined

    }
}
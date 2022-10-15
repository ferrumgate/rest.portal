
import { cloneSecurityProfile, SecurityProfile } from "./securityProfile";

export interface Group {
    id: string;
    name: string;
    labels: string[];
    isEnabled: boolean;
    securityProfile?: SecurityProfile;

}

export function cloneGroup(grp: Group): Group {
    return {
        id: grp.id, labels: Array.from(grp.labels || []), name: grp.name, isEnabled: grp.isEnabled,
        securityProfile: cloneSecurityProfile(grp.securityProfile)

    }
}
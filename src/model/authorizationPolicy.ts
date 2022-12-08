import { AuthorizationProfile, cloneAuthorizationProfile } from "./authorizationProfile";

export interface AuthorizationRule {
    id: string;
    name: string;
    networkId: string;
    userOrgroupIds: string[];
    serviceId: string;
    profile: AuthorizationProfile;
    isEnabled: boolean;
    insertDate: string;
    updateDate: string;

}

export function cloneAuthorizationRule(val: AuthorizationRule): AuthorizationRule {
    return {
        id: val.id,
        name: val.name,
        networkId: val.networkId,
        userOrgroupIds: val.userOrgroupIds ? Array.from(val.userOrgroupIds) : [],
        serviceId: val.serviceId,
        isEnabled: val.isEnabled,
        profile: cloneAuthorizationProfile(val.profile),
        insertDate: val.insertDate,
        updateDate: val.updateDate
    }
}

export interface AuthorizationPolicy {
    id: string
    rules: AuthorizationRule[];
    insertDate: string;
    updateDate: string;

}
import { AuthorizationProfile, cloneAuthorizationProfile } from "./authorizationProfile";

export interface AuthorizationRule {
    id: string;
    name: string;
    networkId: string;
    userOrgroupIds: string[];
    serviceId: string;
    profile: AuthorizationProfile;
    action: 'allow' | 'drop';
}

export function cloneAuthorizationRule(val: AuthorizationRule): AuthorizationRule {
    return {
        id: val.id,
        name: val.name,
        networkId: val.networkId,
        userOrgroupIds: val.userOrgroupIds ? Array.from(val.userOrgroupIds) : [],
        serviceId: val.serviceId,
        action: val.action,
        profile: cloneAuthorizationProfile(val.profile)
    }
}

export interface AuthorizationPolicy {
    id: string
    rules: AuthorizationRule[];
    insertDate: string;
    updateDate: string;

}
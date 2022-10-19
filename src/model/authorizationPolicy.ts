import { AuthorizationProfile } from "./authorizationProfile";

export interface AuthorizationRule {
    id: string;
    name: string;
    networkId: string;
    userOrgroupId: string[];
    serviceId: string;
    profile: AuthorizationProfile;
    action: 'allow' | 'drop';
}

export interface AuthorizationPolicy {
    id: string
    rules: AuthorizationRule[];
    insertDate: string;
    updateDate: string;

}
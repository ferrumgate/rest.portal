import { AuthenticationProfile, cloneAuthenticatonProfile } from "./authenticationProfile";



export interface AuthenticationRule {
    id: string;
    name: string;
    networkId: string;
    userOrgroupIds: string[];
    profile: AuthenticationProfile;
    isEnabled: boolean;
    action: 'allow' | 'deny';

}
export function cloneAuthenticationRule(val: AuthenticationRule): AuthenticationRule {
    return {
        id: val.id,
        action: val.action,
        name: val.name,
        networkId: val.networkId,
        userOrgroupIds: val.userOrgroupIds ? Array.from(val.userOrgroupIds) : [],
        profile: cloneAuthenticatonProfile(val.profile),
        isEnabled: val.isEnabled
    }
}


export interface AuthenticationPolicy {
    id: string
    rules: AuthenticationRule[];
    insertDate: string;
    updateDate: string

}
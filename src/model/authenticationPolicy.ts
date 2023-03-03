import { AuthenticationProfile, cloneAuthenticatonProfile } from "./authenticationProfile";



export interface AuthenticationRule {
    id: string;
    name: string;
    networkId: string;
    userOrgroupIds: string[];
    profile: AuthenticationProfile;
    isEnabled: boolean;
    insertDate: string;
    updateDate: string;


}
export function cloneAuthenticationRule(val: AuthenticationRule): AuthenticationRule {
    return {
        id: val.id,
        name: val.name,
        networkId: val.networkId,
        userOrgroupIds: val.userOrgroupIds ? Array.from(val.userOrgroupIds) : [],
        profile: cloneAuthenticatonProfile(val.profile),
        isEnabled: val.isEnabled, updateDate: val.updateDate, insertDate: val.insertDate,
    }
}


export interface AuthenticationPolicy {
    rules: AuthenticationRule[];
    rulesOrder: string[];

}
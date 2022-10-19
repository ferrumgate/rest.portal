import { AuthenticationProfile } from "./authenticationProfile";



export interface AuthenticationRule {
    id: string;
    name: string;
    networkId: string;
    userOrgroupId: string[];
    profile: AuthenticationProfile;
    action: 'allow' | 'drop';

}


export interface AuthenticationPolicy {
    id: string
    rules: AuthenticationRule[];
    insertDate: string;
    updateDate: string

}
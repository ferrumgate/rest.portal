import { Role } from "./rbac";
import { SecurityProfile } from "./securityProfile";

export interface User {
    id: string;
    name: string;
    username: string;
    password?: string;
    source: string;
    //[key: string]: any;
    groupIds: string[];
    isVerified?: boolean;
    isLocked?: boolean;
    is2FA?: boolean;
    twoFASecret?: string;
    insertDate: string;
    updateDate: string;
    isOnlyApiKey?: boolean;
    apiKey?: string;
    roleIds?: string[];
    email?: string;
    //isEmailVerified: boolean;
    /**
     * if client has problem with it networks settings
     */
    networkSettings?: UserOverrideNetworkSettings[];

    /**
     * security profile for user
     */
    securityProfile?: SecurityProfile;

}

/**
 * if user needs to override some settings for a network
 */
export interface UserOverrideNetworkSettings {
    networkId: string;
    ip?: string;
    serviceNetwork?: string;
}



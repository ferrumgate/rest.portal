import { Role } from "./rbac";

export interface User {
    id: string;
    name: string;
    email: string;
    password?: string;
    source: string;
    [key: string]: any;
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

}



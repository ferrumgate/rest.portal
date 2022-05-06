
export interface User {
    id: string;
    name: string;
    email: string;
    password?: string;
    source: string;
    [key: string]: any;
    groupIds: string[];
    isVerified?: boolean;
}
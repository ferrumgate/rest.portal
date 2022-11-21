export interface AuthSession {
    id: string;
    userId: string;
    username: string;
    ip: string;
    insertDate: string;
    lastSeen: string;
    is2FA: boolean;
    //isPAM: boolean;
    source: string;
}
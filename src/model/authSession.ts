export interface AuthSession {
    id: string;
    userId: string;
    ip: string;
    insertDate: string;
    lastSeen: string;
    is2FA: boolean;
    isPAM: boolean;
    source: string;
}
export interface PamRequest {
    id: string;
    authzRuleId: string;
    trackId: string;
    userId: string;
    username: string;
    insertDate: string;
    status: 'waiting' | 'accepted' | 'denied'
}

/**
 * @summary defines  a PAM access permission
 */
export interface Pam {
    id: string;
    authzRuleId: string;
    trackId: string;
    who?: string;
    by?: string;
    insertDate: string;
}
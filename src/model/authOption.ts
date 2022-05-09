

export interface AuthGoogle {
    clientID: string,
    clientSecret: string,
    //callbackURL: string will  be ${url}/api/auth/google/callback
}
export interface AuthLinkedIn {
    clientID: string,
    clientSecret: string,
    //callbackURL: string will  be ${url}/api/auth/linkedin/callback
}
export interface AuthOption {
    google?: AuthGoogle,
    linkedin?: AuthLinkedIn
}
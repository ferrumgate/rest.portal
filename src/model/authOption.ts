

export interface AuthGoogle {
    clientID: string,
    clientSecret: string,
    //callbackURL: string will  be ${url}/login/google/callback
}
export interface AuthLinkedIn {
    clientID: string,
    clientSecret: string,
    //callbackURL: string will  be ${url}/login/linkedin/callback
}
export interface AuthOption {
    google?: AuthGoogle,
    linkedin?: AuthLinkedIn
}
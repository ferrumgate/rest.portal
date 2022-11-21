export interface AuthorizationProfile {
    is2FA: boolean;

}

export function cloneAuthorizationProfile(val: AuthorizationProfile): AuthorizationProfile {
    return {
        is2FA: val.is2FA,
    }
}
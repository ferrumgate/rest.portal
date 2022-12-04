/**
 * @description Base exception 
 */
export class RestfullException extends Error {

    /**
     * custom your message
     */
    message: string;
    /**
     * and number like http codes
     */
    status: number;
    /**
     * code as string for multi culture 
     */
    code: string;

    codeInternal?: string;


    constructor(status: number, code: string, codeInternal: string, message: string) {
        super();
        this.status = status;
        this.message = message;
        this.code = code;
        this.codeInternal = codeInternal;
    }
}


/**
 * base error codes for @see RestfullException code
 */
export class ErrorCodes {

    static ErrNotAuthenticated: string = 'ErrNotAuthenticated';
    static ErrNotAuthorized: string = 'ErrNotAuthorized';
    static ErrApiKeyIsNotValid: string = 'ErrApiKeyIsNotValid';
    static ErrTunnelKeyIsNotValid: string = 'ErrTunnelKeyIsNotValid';
    static ErrExchangeKeyIsNotValid: string = 'ErrExchangeKeyIsNotValid';
    static ErrBadArgument: string = 'ErrBadArgument';
    static ErrNotFound: string = 'ErrNotFound';
    static ErrInternalError: string = 'ErrInternalError';
    static ErrNotEnoughRight: string = 'ErrNotEnoughRight';
    static ErrTooManyRequests: string = 'ErrTooManyRequests';
    static ErrPasswordPolicy: string = 'ErrPasswordPolicy';
    static ErrEmailIsInvalid: string = 'ErrEmailIsInvalid';
    static ErrCaptchaRequired: string = 'ErrCaptchaRequired';
    static ErrJWTVerifyFailed: string = 'ErrJWTVerifyFailed';
    static ErrUserLockedOrNotVerified: string = 'ErrUserLockedOrNotVerified';
    static ErrUserSourceNotVerified: string = 'ErrUserSourceNotVerified';
    static ErrUserSourceConflict: string = 'ErrUserSourceConflict';
    static ErrCaptchaVerifyFailed: string = 'ErrCaptchaVerifyFailed';
    static Err2FAVerifyFailed: string = 'Err2FAVerifyFailed';
    static ErrTunnelFailed: string = 'ErrTunnelFailed';
    static ErrIpAssignFailed: string = 'ErrIpAssignFailed';
    static ErrTrackIdAssignFailed: string = 'ErrTrackIdAssignFailed';
    static ErrAllreadyConfigured: string = 'ErrAllreadyConfigured';
    static ErrNotConfigured: string = 'ErrNotConfigured';
    static ErrMethodNotAllowed: string = 'ErrMethodNotAllowed';
    static ErrNetworkCidrNotValid: string = 'ErrNetworkCidrNotValid';
    static ErrUrlNotValid: string = 'ErrUrlNotValid';
    static ErrDomainNotValid: string = 'ErrDomainNotValid';
    static ErrEmptyNotValid: string = 'ErrEmptyNotValid';
    static ErrNotExists: string = 'ErrNotExists';
    static ErrExists: string = 'ErrNotExists';
    static ErrAllreadyExits: string = 'ErrAllreadyExits';
    static ErrDataVerifyFailed: string = 'ErrDataVerifyFailed';
    static ErrDisabledSource: string = 'ErrDisabledSource';
    static ErrNoAdminUserLeft: string = 'ErrNoAdminUserLeft';
    static ErrNetworkNotFound: string = 'ErrNetworkNotFound';
    static ErrNotInLdapGroups: string = 'ErrNotInLdapGroups';
    static ErrKeyLengthSmall: string = 'ErrKeyLengthSmall';

}


export class ErrorCodesInternal extends ErrorCodes {
    static ErrTunnelNotFoundOrNotValid: string;
    static ErrTunnelNotFound: string;
    static ErrTunnelNotValid: string;
    static ErrClientNetworkNotValid: string;
    static ErrIpPoolIsOver: string;
    static ErrUserNotFound: string;
    static ErrServiceNotFound: string;
    static ErrServiceNotValid: string;
    static ErrNetworkNotValid: string;
    static ErrNoRuleMatch: string;
    static ErrRuleDenyMatch: string;
    static ErrGatewayNotFound: string;
    static ErrGatewayNotValid: string;
    static ErrSessionNotFound: string;
    static ErrUserSessionNotFoundInvalid: string;
    static ErrSessionInvalid: string;
    static ErrInputNotANumber: string;
    static ErrInputNotExists: string;
    static ErrInputEmpty: string;
    static ErrInputArrayEmpty: string;
    static ErrInputExists: string;
    static ErrTokenInvalid: string;
    static ErrEmailSend: string;
    static ErrKeyNotFound: string;
    static ErrServiceCidrNotValid: string;
    static ErrSystemServiceDelete: string;

    static ErrAuthnRuleNotFound: string;
    static ErrAuthzRuleNotFound: string;
    static ErrAuthzPolicyNotFound: string;
    static ErrAuthnPolicyNotFound: string;
    static ErrGroupNotFound: string;
    static ErrAuthMethodNotFound: string;
    static ErrAuthMethodNoSuccess: string;
    static ErrAdminUserNotFound: string;
    static ErrUsernameOrPasswordInvalid: string;
    static ErrRateLimitReached: string;

}
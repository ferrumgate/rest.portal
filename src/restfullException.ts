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
    static ErrCertificateVerifyFailed: string = 'ErrCertificateVerifyFailed';
    static ErrUserLockedOrNotVerified: string = 'ErrUserLockedOrNotVerified';
    static ErrUserSourceNotVerified: string = 'ErrUserSourceNotVerified';
    static ErrUserSourceConflict: string = 'ErrUserSourceConflict';
    static ErrCaptchaVerifyFailed: string = 'ErrCaptchaVerifyFailed';
    static Err2FAVerifyFailed: string = 'Err2FAVerifyFailed';
    static Err2FANeeds: string = 'Err2FANeeds';
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
    static ErrExists: string = 'ErrExists';
    static ErrAllreadyExits: string = 'ErrAllreadyExits';
    static ErrDataVerifyFailed: string = 'ErrDataVerifyFailed';
    static ErrDisabledSource: string = 'ErrDisabledSource';
    static ErrNoAdminUserLeft: string = 'ErrNoAdminUserLeft';
    static ErrNetworkNotFound: string = 'ErrNetworkNotFound';
    static ErrNotInLdapGroups: string = 'ErrNotInLdapGroups';
    static ErrKeyLengthSmall: string = 'ErrKeyLengthSmall';
    static ErrInputNullOrUndefined: string = "ErrInputNullOrUndefined";
    static ErrLimitedModeIsWorking: string = 'ErrLimitedModeIsWorking';
    static ErrConflictData: string = 'ErrConflictData';
    static ErrSystemIsNotReady: string = "ErrConfigIsNotReady";
    static ErrEmailConfigNeed: string = 'ErrEmailConfigNeed';
    static ErrFqdnIsNotValid: string = 'ErrFqdnIsNotValid';
    static ErrIpNotValid: string = 'ErrIpNotValid'
    static ErrSystemParameter: string = "ErrSystemParameter";
    static ErrCertificateIsNotValid: string = 'ErrCertificateIsNotValid';
    static ErrTimeout: string = 'ErrTimeout';

}


export class ErrorCodesInternal extends ErrorCodes {
    static ErrTunnelNotFoundOrNotValid: string = "ErrTunnelNotFoundOrNotValid";
    static ErrTunnelNotFound: string = "ErrTunnelNotFound";
    static ErrTunnelNotValid: string = "ErrTunnelNotValid";
    static ErrClientNetworkNotValid: string = "ErrClientNetworkNotValid";
    static ErrIpPoolIsOver: string = "ErrIpPoolIsOver";
    static ErrUserNotFound: string = "ErrUserNotFound";
    static ErrServiceNotFound: string = "ErrServiceNotFound";
    static ErrServiceNotValid: string = "ErrServiceNotValid";
    static ErrNetworkNotValid: string = "ErrNetworkNotValid";
    static ErrNoRuleMatch: string = "ErrNoRuleMatch";
    static ErrNo2FAMatch: string = "ErrNo2FAMatch";
    static ErrNoLocationMatch: string = "ErrNoLocationMatch";
    static ErrNoTimeMatch: string = "ErrNoTimeMatch";
    static ErrRuleDenyMatch: string = "ErrRuleDenyMatch";
    static ErrGatewayNotFound: string = "ErrGatewayNotFound";
    static ErrGatewayNotValid: string = "ErrGatewayNotValid";
    static ErrSessionNotFound: string = "ErrSessionNotFound";
    static ErrUserSessionNotFoundInvalid: string = "ErrUserSessionNotFoundInvalid";
    static ErrSessionInvalid: string = "ErrSessionInvalid";
    static ErrInputNotANumber: string = "ErrInputNotANumber";
    static ErrInputNotExists: string = "ErrInputNotExists";
    static ErrInputEmpty: string = "ErrInputEmpty";
    static ErrInputArrayEmpty: string = "ErrInputArrayEmpty";
    static ErrInputExists: string = "ErrInputExists";
    static ErrTokenInvalid: string = "ErrTokenInvalid";
    static ErrEmailSend: string = "ErrEmailSend";
    static ErrKeyNotFound: string = "ErrKeyNotFound";
    static ErrServiceCidrNotValid: string = "ErrServiceCidrNotValid";
    static ErrSystemServiceDelete: string = "ErrSystemServiceDelete";
    static ErrAuthnRuleNotFound: string = "ErrAuthnRuleNotFound";
    static ErrAuthzRuleNotFound: string = "ErrAuthzRuleNotFound";
    static ErrAuthzPolicyNotFound: string = "ErrAuthzPolicyNotFound";
    static ErrAuthnPolicyNotFound: string = "ErrAuthnPolicyNotFound";
    static ErrGroupNotFound: string = "ErrGroupNotFound";
    static ErrAuthMethodNotFound: string = "ErrAuthMethodNotFound";
    static ErrAuthMethodNoSuccess: string = "ErrAuthMethodNoSuccess";
    static ErrAdminUserNotFound: string = "ErrAdminUserNotFound";
    static ErrUsernameOrPasswordInvalid: string = "ErrUsernameOrPasswordInvalid";
    static ErrRateLimitReached: string = "ErrRateLimitReached";
    static ErrOnlyAuthLocalIsValid: string = "ErrOnlyAuthLocalIsValid";
    static ErrIpIntelligenceSourceNotFound: string = "ErrIpIntelligenceSourceNotFound";
    static ErrIpIntelligenceBWItemNotFound: string = "ErrIpIntelligenceBWItemNotFound";
    static ErrDevicePostureNotFound: string = 'ErrDevicePostureNotFound';
    static ErrIpIntelligenceCustomBlackListContains: string = 'ErrIpIntelligenceCustomBlackListContains';
    static ErrIpIntelligenceBlackListContains: string = 'ErrIpIntelligenceBlackListContains';
    static ErrIpIntelligenceBlackIp: string = 'ErrIpIntelligenceBlackIp';
    static ErrNoDevicePostureMatch: string = 'ErrNoDevicePostureMatch';
    static ErrDevicePostureOsTypeNotAllowed: string = 'ErrDevicePostureOsTypeNotAllowed'
    static ErrDevicePostureClientVersionNotAllowed: string = 'ErrDevicePostureClientVersionNotAllowed';
    static ErrDevicePostureFirewallNotAllowed: string = 'ErrDevicePostureFirewallNotAllowed';
    static ErrDevicePostureAntivirusNotAllowed: string = 'ErrDevicePostureAntivirusNotAllowed';
    static ErrDevicePostureDiscEncryptedNotAllowed: string = 'ErrDevicePostureDiscEncryptedNotAllowed';
    static ErrDevicePostureMacNotAllowed: string = 'ErrDevicePostureMacNotAllowed';
    static ErrDevicePostureSerialNotAllowed: string = 'ErrDevicePostureSerialNotAllowed';
    static ErrDevicePostureFileNotAllowed: string = 'ErrDevicePostureFileNotAllowed';
    static ErrDevicePostureRegisryNotAllowed: string = 'ErrDevicePostureRegisryNotAllowed';
    static ErrDevicePostureProcessNotAllowed: string = 'ErrDevicePostureProcessNotAllowed';
    static ErrDevicePostureNotChecked: string = 'ErrDevicePostureNotChecked';
    static ErrSaveNewUserDisabled: string = 'ErrSaveNewUserDisabled'



}
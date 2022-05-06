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

    constructor(status: number, code: string, message: string) {
        super();
        this.status = status;
        this.message = message;
        this.code = code;
    }
}


/**
 * base error codes for @see RestfullException code
 */
export class ErrorCodes {

    static ErrNotAuthorized: string = 'ErrNotAuthorized';
    static ErrApiKeyIsNotValid: string = 'ErrApiKeyIsNotValid';
    static ErrBadArgument: string = 'ErrBadArgument';
    static ErrNotFound: string = 'ErrNotFound';
    static ErrInternalError: string = 'ErrInternalError';
    static ErrNotEnoughRight: string = 'ErrNotEnoughRight';
    static ErrTooManyRequests: string = 'ErrTooManyRequests';
    static ErrPasswordPolicy: string = 'ErrPasswordPolicy';
    static ErrEmailIsInvalid: string = 'ErrEmailIsInvalid';
    static ErrCaptchaRequired: string = 'ErrCaptchaRequired';

}
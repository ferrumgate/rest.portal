
/**
 * @summary email configuration option, by google or office365 or smtp
 */
export interface EmailOption {
    type: 'google' | 'office365' | 'smtp' | 'unknown',
    fromname: string,
    user: string,
    pass: string,
    [key: string]: any;
}

/**
 * @summary email configuration option, by google or office365 or smtp
 */
export interface EmailSettings {
    type: 'google' | 'office365' | 'smtp' | 'unknown',
    fromname: string,
    user: string,
    pass: string,
    [key: string]: any;
}

/**
 * @summary email configuration option, by google or office365 or smtp
 */
export interface EmailSetting {
    type: 'google' | 'office365' | 'smtp' | 'empty',
    fromname: string,
    user: string,
    pass: string,
    [key: string]: any;
}


export interface EmailOption {
    type: 'google' | 'office365' | 'smtp' | 'unknown',
    fromname: string,
    user: string,
    pass: string,
    [key: string]: any;
}
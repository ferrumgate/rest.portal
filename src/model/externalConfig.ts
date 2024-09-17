import { Captcha } from "./captcha";

export interface ExternalConfig {
    ids?: string[];
    insertDate?: string;
    updateDate?: string;
}
export interface CaptchaExtended extends Captcha {
    externalId: string;
}

export interface FerrumCloudConfig {
    captcha?: CaptchaExtended
}
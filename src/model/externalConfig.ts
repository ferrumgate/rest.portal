import { Captcha } from "./captcha";
import { CloudSetting } from "./cloudSetting";

export interface ExternalConfig {
    ids?: string[];
    insertDate?: string;
    updateDate?: string;
}
export interface CaptchaExtended extends Captcha {
    externalId: string;
}

export interface CloudSettingExtended extends CloudSetting {
    externalId: string;
}

//this class comes from dome project
//DomeExtraConfig 
export interface FerrumCloudConfig {
    captcha?: CaptchaExtended,
    cloud?: CloudSettingExtended
}
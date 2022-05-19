import Axios, { AxiosRequestConfig } from "axios";
import { ErrorCodes } from "../restfullException";
import { RestfullException } from "../restfullException";
import { ConfigService } from "./configService";

/**
 * services captcha related functions
 */
export class CaptchaService {


    constructor(private config: ConfigService) {

    }

    async check(captcha: string, action?: string) {
        const captchaKeys = await this.config.getCaptcha();
        const secretKey = captchaKeys.server || 'secretkey';
        let options: AxiosRequestConfig = {
            timeout: 15 * 1000,
            /* headers: {
                ApiKey: ''
            } */
        };
        const verificationURL = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captcha}`

        const response = await Axios.get(verificationURL, options);
        const body = response.data
        if (body.success !== undefined && !body.success) {
            throw new RestfullException(400, ErrorCodes.ErrCaptchaVerifyFailed, 'captcha verify failed');
        }
    }
}
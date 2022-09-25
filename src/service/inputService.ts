
import { passwordStrength } from 'check-password-strength'
import emailValidator from 'email-validator';
import { logger } from '../common';
import { ErrorCodes, RestfullException } from '../restfullException';
import isCidr from 'ip-cidr';
import validator from 'validator';

/**
 * checks input data
 */
export class InputService {
    checkEmail(email: string) {
        if (!email)
            throw new RestfullException(400, ErrorCodes.ErrEmailIsInvalid, 'email is invalid');
        if (!email.trim())
            throw new RestfullException(400, ErrorCodes.ErrEmailIsInvalid, 'email is invalid');
        if (!this.isEmail(email))
            throw new RestfullException(400, ErrorCodes.ErrEmailIsInvalid, 'email is invalid');

    }
    isEmail(email: string) {
        return emailValidator.validate(email);
    }
    checkPasswordPolicy(pass: string) {
        const result = passwordStrength(pass);
        //if (result.id < 2)
        //    throw new RestfullException(400, ErrorCodes.ErrPasswordPolicy, 'password policy does not meet requirement');
        if (result.length < 8) {
            logger.error(`password length is < 8`)
            throw new RestfullException(400, ErrorCodes.ErrPasswordPolicy, 'password length at least 8');
        }
        if (!result.contains.includes('lowercase') || !result.contains.includes('uppercase') || !result.contains.includes('number')) {
            logger.error(`password must include lowercase, uppercase and a number at least`);
            throw new RestfullException(400, ErrorCodes.ErrPasswordPolicy, 'password must include lowercase, uppercase and a number');
        }


    }
    /**
     * 
     * @param net 
     * @returns throw exception or return 4 (ipv4) or 6 (ipv6)
     */
    checkCidr(net: string) {
        if (!net) throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'cidr is invalid');
        const result = isCidr.isValidCIDR(net);
        if (!result) throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'cidr is invalid');

    }
    /**
     * @summary check if fqdn is valid
     * @param domain 
     */
    checkDomain(domain: string) {
        if (!domain) throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'fqdn is invalid');
        const result = validator.isFQDN(domain);
        if (!result) throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'fqdn is invalid');
    }

    /**
     * @summary check if login url is valid
     * @param url 
     */
    checkUrl(url: string) {
        if (!url) throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'url is invalid');
        const result = (url.startsWith('http://') || url.startsWith('https://')) && validator.isURL(url);
        if (!result) throw new RestfullException(400, ErrorCodes.ErrBadArgument, 'url is invalid');
    }

}
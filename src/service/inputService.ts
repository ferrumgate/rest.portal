
import { passwordStrength } from 'check-password-strength'
import emailValidator from 'email-validator';
import { logger } from '../common';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../restfullException';
import isCidr from 'ip-cidr';
import validator from 'validator';

/**
 * @summary checks input data
 */
export class InputService {

    checkEmail(email: string) {
        if (!email)
            throw new RestfullException(400, ErrorCodes.ErrEmailIsInvalid, ErrorCodes.ErrEmailIsInvalid, 'email is invalid');
        if (!email.trim())
            throw new RestfullException(400, ErrorCodes.ErrEmailIsInvalid, ErrorCodes.ErrEmailIsInvalid, 'email is invalid');
        if (!this.isEmail(email))
            throw new RestfullException(400, ErrorCodes.ErrEmailIsInvalid, ErrorCodes.ErrEmailIsInvalid, 'email is invalid');

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
            throw new RestfullException(400, ErrorCodes.ErrPasswordPolicy, ErrorCodes.ErrPasswordPolicy, 'password length at least 8');
        }
        if (!result.contains.includes('lowercase') || !result.contains.includes('uppercase') || !result.contains.includes('number')) {
            logger.error(`password must include lowercase, uppercase and a number at least`);
            throw new RestfullException(400, ErrorCodes.ErrPasswordPolicy, ErrorCodes.ErrPasswordPolicy, 'password must include lowercase, uppercase and a number');
        }


    }
    /**
     * 
     * @param net 
     * @returns throw exception or return 4 (ipv4) or 6 (ipv6)
     */
    checkCidr(net: string) {
        if (!net) throw new RestfullException(400, ErrorCodes.ErrNetworkCidrNotValid, ErrorCodes.ErrNetworkCidrNotValid, 'cidr is invalid');
        const result = isCidr.isValidCIDR(net);
        if (!result) throw new RestfullException(400, ErrorCodes.ErrNetworkCidrNotValid, ErrorCodes.ErrNetworkCidrNotValid, 'cidr is invalid');

    }
    /**
     * @summary check if fqdn is valid
     * @param domain 
     */
    checkDomain(domain: string) {
        if (!domain) throw new RestfullException(400, ErrorCodes.ErrDomainNotValid, ErrorCodes.ErrDomainNotValid, 'fqdn is invalid');
        const result = validator.isFQDN(domain, { require_tld: false });
        if (!result) throw new RestfullException(400, ErrorCodes.ErrDomainNotValid, ErrorCodes.ErrDomainNotValid, 'fqdn is invalid');
    }

    checkHost(domainIp: string) {
        if (!domainIp) throw new RestfullException(400, ErrorCodes.ErrDomainNotValid, ErrorCodes.ErrDomainNotValid, 'host is invalid');
        let domain = domainIp;
        let port = '9999';
        if (domainIp.includes(":")) {
            let parts = domainIp.split(":");
            port = parts[1];
            domain = parts[0];
        }
        const vport = validator.isPort(port)

        const vresult = validator.isFQDN(domain, { require_tld: false }) || validator.isIP(domain);
        if (!vresult || !vport) throw new RestfullException(400, ErrorCodes.ErrDomainNotValid, ErrorCodes.ErrDomainNotValid, 'host is invalid');

    }

    /**
     * @summary check if login url is valid
     * @param url 
     */
    checkUrl(url: string) {
        if (!url) throw new RestfullException(400, ErrorCodes.ErrUrlNotValid, ErrorCodes.ErrUrlNotValid, 'url is invalid');
        const result = (url.startsWith('http://') || url.startsWith('https://')) && (validator.isURL(url, { require_tld: false }) || url.includes('localhost'));
        if (!result) throw new RestfullException(400, ErrorCodes.ErrUrlNotValid, ErrorCodes.ErrUrlNotValid, 'url is invalid');
    }

    checkNotEmpty(value?: string) {
        if (!value) throw new RestfullException(400, ErrorCodes.ErrEmptyNotValid, ErrorCodesInternal.ErrInputEmpty, 'property is empty');

    }

    checkIfExists(value: any, errorMsg?: string) {
        if (!value) {
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrInputNotExists, errorMsg || 'input is invalid');
        }
    }
    checkIfNotExits(value: any) {
        if (value) {
            throw new RestfullException(400, ErrorCodes.ErrExists, ErrorCodesInternal.ErrInputExists, 'input is invalid');
        }
    }
    checkArrayNotEmpty(value: any[]) {
        if (!Array.isArray(value))
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrInputArrayEmpty, 'input is invalid');
        if (!value.length)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrInputArrayEmpty, 'input is invalid');
    }
    checkIsNumber(value: any) {
        if (value == undefined || value == null) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrInputNotANumber, 'input is invalid');
        let val = Number(value);
        if (Number.isNaN(val)) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrInputNotANumber, 'input is invalid');

    }
    checkStringLength(exchangeKey: string, len: number) {
        if (exchangeKey.length < len)
            throw new RestfullException(400, ErrorCodes.ErrKeyLengthSmall, ErrorCodes.ErrKeyLengthSmall, 'length is invalid');
    }
    checkNotNullOrUndefined(val?: any) {
        if (val == null || val == undefined)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrInputNullOrUndefined, 'input is invalid');
    }

}
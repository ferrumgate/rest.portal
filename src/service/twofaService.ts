
import * as twofactor from 'node-2fa';
import { ErrorCodes, RestfullException } from '../restfullException';
import { Util } from '../util';

/**
 * @summary 2FA releated functions
 */
export class TwoFAService {
    generateSecret() {
        return twofactor.generateSecret({ name: Util.randomNumberString(16), account: Util.randomNumberString(16) }).secret;
    }

    generateToken(secret: string) {
        return twofactor.generateToken(secret)?.token;
    }

    verifyToken(secret: string, verify: string) {
        const result = twofactor.verifyToken(secret, verify);
        if (result?.delta == 0) return true;
        throw new RestfullException(400, ErrorCodes.Err2FAVerifyFailed, ErrorCodes.Err2FAVerifyFailed, '2fa not verified');
    }


}
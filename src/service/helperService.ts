import { User } from "../model/user";
import { Util } from "../util";
import *  as twofactor from 'node-2fa';

export class HelperService {
    static createUser(source: string, email: string, name: string, password?: string) {
        const user: User = {
            source: source,
            email: email,
            id: Util.randomNumberString(16),
            name: name,
            isLocked: false,
            isVerified: false,
            groupIds: [],
            password: password ? Util.bcryptHash(password) : Util.bcryptHash(Util.createRandomHash(64)),
            is2FA: false,
            twoFASecret: twofactor.generateSecret().secret,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }

        return user;
    }
}
import { User } from "../model/user";
import { Util } from "../util";
import *  as twofactor from 'node-2fa';
import { ErrorCodes, RestfullException } from "../restfullException";
import { RBACDefault } from "../model/rbac";

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
            updateDate: new Date().toISOString(),
            roleIds: [RBACDefault.roleUser.id]//every user is with Role User
        }

        return user;
    }

    static isValidUser(user: User | undefined) {
        if (!user)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'not found');
        if (!user.isVerified)
            throw new RestfullException(401, ErrorCodes.ErrUserLockedOrNotVerified, "locked or not verified user");
        if (user.isLocked)
            throw new RestfullException(401, ErrorCodes.ErrUserLockedOrNotVerified, "locked or not verified user");

    }
}
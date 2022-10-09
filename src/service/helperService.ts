import { User } from "../model/user";
import { Util } from "../util";
import *  as twofactor from 'node-2fa';
import { ErrorCodes, RestfullException } from "../restfullException";
import { RBACDefault } from "../model/rbac";
import { Tunnel } from "../model/tunnel";


export class HelperService {
    static createUser(source: string, username: string, name: string, password?: string) {
        const user: User = {
            source: source,
            username: username,
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
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not found');
        if (!user.isVerified)
            throw new RestfullException(401, ErrorCodes.ErrUserLockedOrNotVerified, "locked or not verified user");
        if (user.isLocked)
            throw new RestfullException(401, ErrorCodes.ErrUserLockedOrNotVerified, "locked or not verified user");

    }
    static isFromSource(user: User | undefined, source: string) {
        if (!user)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not found');

        if (user.source != source)
            throw new RestfullException(401, ErrorCodes.ErrUserSourceNotVerified, "user source not verified");
    }



    /**
     * @summary check if tunnel session is valid
     * @param ses 
     */
    static isValidTunnel(tun: Tunnel | undefined) {
        if (!tun)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not found');
        if (!tun.authenticatedTime)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not authenticated');
        if (!tun.tun)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not tunned');
        if (!tun.userId)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not authenticated');
        if (!tun.assignedClientIp)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'not authenticated');
        if (!tun.hostId)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, "not authenticated")
        if (!tun.serviceNetwork)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, "not authenticated")

    }
} {


}
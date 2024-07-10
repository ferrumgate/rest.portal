import * as twofactor from 'node-2fa';
import { AuthSession } from "../model/authSession";
import { RBACDefault } from "../model/rbac";
import { Tunnel } from "../model/tunnel";
import { User } from "../model/user";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { Util } from "../util";

/**
 * @summary a helper class, for widely used functions
 */
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
            throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrUserNotFound, 'not found');
        if (!user.isVerified)
            throw new RestfullException(401, ErrorCodes.ErrUserLockedOrNotVerified, ErrorCodes.ErrUserLockedOrNotVerified, "locked or not verified user");
        if (user.isLocked)
            throw new RestfullException(401, ErrorCodes.ErrUserLockedOrNotVerified, ErrorCodes.ErrUserLockedOrNotVerified, "locked or not verified user");

    }
    static isFromSource(user: User | undefined, source: string) {
        if (!user)
            throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrUserNotFound, 'not found');

        if (user.source != source)
            throw new RestfullException(401, ErrorCodes.ErrUserSourceConflict, ErrorCodes.ErrUserSourceConflict, "user source not verified");
    }



    /**
     * @summary check if tunnel session is valid
     * @param ses 
     */
    static isValidTunnel(tun: Tunnel | undefined) {
        const result = HelperService.isValidTunnelNoException(tun);
        if (result == 'not found')
            throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrTunnelNotFound, result);
        else if (result == 'not authenticated')
            throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrTunnelNotValid, result);
        else if (result)
            throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrTunnelNotValid, result);

    }

    /**
     * @summary check if tunnel session is valid without exception
     * @param 
     * @return error msg or empty message
     */
    static isValidTunnelNoException(tun: Tunnel | undefined) {
        if (!tun)
            return 'not found';
        if (!tun.authenticatedTime)
            return 'not authenticated';
        if (!tun.tun)
            return 'not tunned';
        if (!tun.trackId)
            return 'not tracked';
        if (!tun.userId)
            return 'not authenticated';
        if (!tun.assignedClientIp)
            return 'not authenticated';
        if (!tun.gatewayId)
            return "not authenticated";
        if (!tun.serviceNetwork)
            return "not authenticated";
        return '';

    }
    static isValidSession(session: AuthSession) {
        if (!session)
            throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrSessionNotFound, 'no session');
    }


} 
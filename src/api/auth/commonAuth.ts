import { logger } from "../../common";
import { ActivityLog, ActivityStatus } from "../../model/activityLog";
import { AuthSession } from "../../model/authSession";
import { BaseAuth } from "../../model/authSettings";
import { Tunnel } from "../../model/tunnel";
import { User } from "../../model/user";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../../restfullException";
import { AppService } from "../../service/appService";
import { HelperService } from "../../service/helperService";
import { Util } from "../../util";


/**
 * common user checking function
 * @param user 
 */
export async function checkUser(user?: User, baseAuth?: BaseAuth) {
    if (!user)
        throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrInputNotExists, "not authenticated");
    if (!baseAuth)
        throw new RestfullException(401, ErrorCodes.ErrBadArgument, ErrorCodesInternal.ErrInputNotExists, "not authenticated");
    HelperService.isValidUser(user);
    //I disabled this validation,
    // by this way, a user can also authenticate from another source
    // there is only one risk here that, if two real person uses same email
    // then there is a risk
    //HelperService.isFromSource(user, `${baseAuth.baseType}-${baseAuth.type}`);

}

/**
 * @summary create an activity object if not exists on request and set auth source
 */
export function attachActivitySource(req: any, authSource: string) {
    //important we need to know where auth comes
    if (!req.activity)
        req.activity = {};
    req.activity.authSource = authSource;
    // follow request
    req.activity.requestId = req.activity.requestId || Util.randomNumberString(64);
    req.activity.clientIp = req.activity.clientIp || req.clientIp;

}
/**
 * @summary create an activity object if not exists on request and set username
 */
export function attachActivityUsername(req: any, username?: string) {
    //important we need to know where auth comes
    if (!req.activity)
        req.activity = {};
    req.activity.username = username;
    // follow request
    req.activity.requestId = req.activity.requestId || Util.randomNumberString(64);
    req.activity.clientIp = req.activity.clientIp || req.clientIp;

}

/**
 * @summary create an activity object if not exists on request and set user
 */
export function attachActivityUser(req: any, user?: User) {
    //important we need to know where auth comes
    if (!req.activity)
        req.activity = {};
    req.activity.user = user;
    req.activity.username = user?.username;
    // follow request
    req.activity.requestId = req.activity.requestId || Util.randomNumberString(64);
    req.activity.clientIp = req.activity.clientIp || req.clientIp;

}

/**
 * @summary create an activity object if not exists on request and set user
 */
export function attachActivitySessionId(req: any, id?: string) {
    //important we need to know where auth comes
    if (!req.activity)
        req.activity = {};
    req.activity.sessionId = id;
    // follow request
    req.activity.requestId = req.activity.requestId || Util.randomNumberString(64);
    req.activity.clientIp = req.activity.clientIp || req.clientIp;

}

/**
 * @summary create an activity object if not exists on request and set user
 */
export function attachActivitySession(req: any, session?: AuthSession) {
    //important we need to know where auth comes
    if (!req.activity)
        req.activity = {};
    if (session) {
        req.activity.sessionId = session.id;
        req.activity.authSource = session.source;
        req.activity.is2FA = session.is2FA;
        req.activity.countryCode = session.countryCode;
        req.activity.countryName = session.countryName;
        req.activity.isProxyIp = session.isProxyIp;
        req.activity.isCrawlerIp = session.isCrawlerIp;
        req.activity.isHostingIp = session.isHostingIp;
    }
    // follow request
    req.activity.requestId = req.activity.requestId || Util.randomNumberString(64);
    req.activity.clientIp = req.activity.clientIp || req.clientIp;

}




/**
 * @summary create an activity object if not exists on request and set user
 */
export function attachActivityTunnel(req: any, tunnel?: Tunnel) {
    //important we need to know where auth comes
    if (!req.activity)
        req.activity = {};
    if (tunnel) {
        req.activity.tunnelId = tunnel.id;
        req.activity.trackId = tunnel.trackId;
        req.activity.assignedIp = tunnel.assignedClientIp;
        req.activity.tun = tunnel.tun;
        req.activity.tunType = tunnel.type;
        req.activity.gatewayId = tunnel.gatewayId;
    }
    // follow request
    req.activity.requestId = req.activity.requestId || Util.randomNumberString(64);
    req.activity.clientIp = req.activity.clientIp || req.clientIp;

}






/**
 * @summary create an activity object if not exists on request and set user
 */
export function attachActivity(req: any, activity?: any) {
    //important we need to know where auth comes
    if (!req.activity)
        req.activity = {};
    if (activity) {
        req.activity = {
            ...req.activity,
            ...activity
        }
    }

    // follow request
    req.activity.requestId = req.activity.requestId || Util.randomNumberString(64);
    req.activity.clientIp = req.activity.clientIp || req.clientIp;

}

function getRequestPath(req: any) {
    const path: string = req.baseUrl + req.path;
    if (path.endsWith('/'))
        return path.substring(0, path.length - 1);
    return path;
}

export async function saveActivityError(req: any, type: string, err: any, extFunc?: (log: ActivityLog) => void) {
    try {
        if (!(err instanceof RestfullException))
            return;
        const appService = req.appService as AppService;
        const activityService = appService.activityService;
        const act = req.activity;
        const activity: ActivityLog = {
            requestId: act.requestId || Util.randomNumberString(64),
            type: type,
            username: act.username || '',
            authSource: act.authSource || 'unknown',
            insertDate: new Date().toISOString(),
            ip: act.clientIp || req.clientIp,
            status: ActivityStatus.Success,
            userId: act.user?.id,
            user2FA: act.user?.is2FA,//user needs 2FA            
            sessionId: act.sessionId,
            requestPath: getRequestPath(req),
            //tunnel related data
            assignedIp: act.assignedIp,
            tunnelId: act.tunnelId,
            tun: act.tun,
            tunType: act.tunType,
            trackId: act.trackId,
            gatewayId: act.gatewayId

        }


        activity.status = err.status;
        activity.statusMessage = err.codeInternal || err.code;

        if (extFunc)
            extFunc(activity);
        await activityService.save(activity);
    } catch (err) {
        logger.fatal(err);
    }

}


export async function saveActivity(req: any, type: string, extFunc?: (log: ActivityLog) => void) {
    try {

        const appService = req.appService as AppService;
        const activityService = appService.activityService;
        const act = req.activity;
        const activity: ActivityLog = {
            requestId: act.requestId || Util.randomNumberString(64),
            type: type,
            username: act.username || 'unknown',
            userId: act.user?.id,
            user2FA: act.user?.is2FA,//user needs 2FA
            authSource: act.authSource || 'unknown',
            insertDate: new Date().toISOString(),
            ip: act.clientIp || req.clientIp,
            status: ActivityStatus.Success,
            sessionId: act.sessionId,
            requestPath: getRequestPath(req),
            //tunnel related data
            assignedIp: act.assignedIp,
            tunnelId: act.tunnelId,
            tun: act.tun,
            tunType: act.tunType,
            trackId: act.trackId,
            gatewayId: act.gatewayId
        }
        if (extFunc)
            extFunc(activity);

        await activityService.save(activity);
    } catch (err) {
        logger.fatal(err);
    }

}


export function makePassportName(name: string) {
    return name.toLocaleLowerCase().replace(/[^a-z0-9]/g, '');
}


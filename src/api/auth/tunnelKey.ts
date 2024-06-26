import passport from 'passport';
import passportCustom from 'passport-custom';
import { logger } from '../../common';
import { ActivityLog } from '../../model/activityLog';
import { ErrorCodes, RestfullException } from '../../restfullException';
import { AppService } from '../../service/appService';
import { HelperService } from '../../service/helperService';
import { attachActivitySource, attachActivityUser, attachActivityUsername, saveActivity, saveActivityError } from './commonAuth';

const name = 'tunnelKey';
export function tunnelKeyInit() {
    passport.use(name, new passportCustom.Strategy(
        async (req: any, done: any) => {

            try {

                attachActivitySource(req, name);
                let tunnelKey = req.get('TunnelKey') as string;
                if (!tunnelKey)
                    throw new RestfullException(401, ErrorCodes.ErrTunnelKeyIsNotValid, ErrorCodes.ErrTunnelKeyIsNotValid, 'tunnel key header not found');
                attachActivityUsername(req, tunnelKey);
                logger.info(`passport with tunnelKey: ${tunnelKey}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const tunnelService = appService.tunnelService;
                const sessionService = appService.sessionService;


                const tunnel = await tunnelService.getTunnel(tunnelKey);

                await HelperService.isValidTunnel(tunnel);

                const currentSession = await sessionService.getSession(tunnel?.sessionId || '0');
                req.currentSession = currentSession;



                //set user to request object
                const user = await configService.getUserById(tunnel?.userId || '0');
                attachActivityUser(req, user);
                HelperService.isValidUser(user);
                req.currentUser = user;
                req.currentTunnel = tunnel;


                // TODO  we need a session
                if (!currentSession && user) {
                    req.currentSession = await sessionService.createFakeSession(user, false, req.clientIp, name);
                }

                await saveActivity(req, 'login try', (act: ActivityLog) => {
                    act.assignedIp = tunnel?.assignedClientIp;
                    act.tunnelId = tunnel?.id;
                    act.is2FA = tunnel?.is2FA;
                    act.gatewayId = tunnel?.gatewayId;
                    act.serviceId = tunnel?.sessionId;
                    act.trackId = tunnel?.trackId;
                    act.tun = tunnel?.tun;
                    act.tunType = tunnel?.type;

                });
                return done(null, user);

            } catch (err) {
                await saveActivityError(req, 'login try', err);
                return done(null, null, err);
            }

        }
    ));
    return name;
}
export function tunnelKeyUnuse() {
    passport.unuse(name)
}



import passport from 'passport';
import * as passportapikey from 'passport-headerapikey';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { ErrorCodes, RestfullException } from '../../restfullException';
import { HelperService } from '../../service/helperService';
import { Tunnel } from '../../model/tunnel';
import passportCustom from 'passport-custom';

const name = 'headertunnelkey';
export function tunnelKeyInit() {
    passport.use(name, new passportCustom.Strategy(
        async (req: any, done: any) => {

            try {


                let tunnelkey = req.get('TunnelKey') as string;
                if (!tunnelkey)
                    throw new RestfullException(401, ErrorCodes.ErrTunnelKeyIsNotValid, 'tunnel key header not found');

                logger.info(`passport with tunnelkey: ${tunnelkey})}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;

                if (!tunnelkey)
                    throw new RestfullException(400, ErrorCodes.ErrBadArgument, "bad argument");
                const tunnel = (await redisService.hgetAll(`/tunnel/${tunnelkey}`)) as unknown as Tunnel;
                await HelperService.isValidTunnel(tunnel);
                //set user to request object
                const user = await configService.getUserById(tunnel.userId || '0');
                HelperService.isValidUser(user);
                req.currentUser = user;
                req.currentTunnel = tunnel;
                return done(null, user);

            } catch (err) {
                return done(null, null, err);
            }

        }
    ));
    return name;
}
export function tunnelKeyUnuse() {
    passport.unuse(name)
}
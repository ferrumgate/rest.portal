
import { localInit } from "./local";
import { apiKeyInit } from "./apikey";
import { jwtInit } from "./jwt";
import { oauthGoogleInit } from "./google";
import { oauthLinkedinInit } from "./linkedin";
import { AppService } from "../../service/appService";
import { tunnelKeyInit } from "./tunnelKey";
import { activeDirectoryInit } from "./activeDirectory";
import passport from "passport";
import { ErrorCodes, RestfullException } from "../../restfullException";
import { logger } from "../../common";

// check if config changed
let lastConfigServiceUpdateTime = '';
export const passportConf: { activeStrategies: string[] } = {
    activeStrategies: []
}

export async function passportInit(req: any, res: any, next: any) {

    const configService = (req.appService as AppService).configService;
    if (configService.lastUpdateTime != lastConfigServiceUpdateTime) {//if config changed
        const auth = await configService.getAuthSettings();
        const domain = await configService.getDomain();
        const url = await configService.getUrl();

        let activeStrategies = [];
        //init local 
        const local = localInit();
        activeStrategies.push(local);
        //init apikey
        const apikey = apiKeyInit();
        activeStrategies.push(apikey);
        //init jwt verification
        const jwt = jwtInit();
        activeStrategies.push(jwt);
        // init sessionkey
        const tunnelkey = tunnelKeyInit();
        activeStrategies.push(tunnelkey);
        // init google
        const oauthGoogle = auth.oauth?.providers.find(x => x.type == 'google');
        if (oauthGoogle && oauthGoogle.isEnabled) {
            const google = oauthGoogleInit(oauthGoogle, url);
            activeStrategies.push(google);
        }
        // init linkedin
        const oauthLinkedin = auth.oauth?.providers.find(x => x.type == 'linkedin');
        if (oauthLinkedin && oauthLinkedin.isEnabled) {
            const linkedin = oauthLinkedinInit(oauthLinkedin, url);
            activeStrategies.push(linkedin);
        }
        // init active directory
        const activeDirectory = auth.ldap?.providers.find(x => x.type == 'activedirectory');
        if (activeDirectory && activeDirectory.isEnabled) {
            const activedirectory = activeDirectoryInit(activeDirectory, url);
            activeStrategies.push(activedirectory);
        }
        passportConf.activeStrategies = activeStrategies;
        lastConfigServiceUpdateTime = configService.lastUpdateTime;

    }
    next();
}
export function passportFilterActiveStrategies(methods: string[]) {
    //check according to initted methods;
    return (methods as string[]).filter(x => passportConf.activeStrategies.includes(x));
}


export async function passportAuthenticate(req: any, res: any, next: any, strategyList: string[]) {
    try {
        //this part must be array, otherwise
        let strategyNames = Array.isArray(strategyList) ? strategyList.flat() : []
        if (!Array.isArray(strategyList) && strategyList) {
            strategyNames.push(strategyList);
        }
        strategyNames = passportFilterActiveStrategies(strategyNames);
        //becarefull about changing this function
        // this gives authentication to the system
        const auth = passport.authenticate(strategyNames, { session: false, passReqToCallback: true }, async (err, user, info, status) => {

            if (err)
                next(err);
            else
                if (user)
                    next();
                else {
                    if (!Array.isArray(info))
                        info = [info];
                    let results = (info as any[]);
                    if (!results.length)
                        next(new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'no method'));
                    else {
                        const errors = results.filter(y => y);
                        const success = results.filter(y => !y);
                        if (success.length)
                            next();
                        else {
                            const error = errors.find(x => x instanceof RestfullException);
                            next(error || new RestfullException(401, ErrorCodes.ErrNotAuthenticated, 'no success'));
                        }


                    }

                }

        })
        auth(req, res, next);
    } catch (err: any) {
        next(err);
    }
}



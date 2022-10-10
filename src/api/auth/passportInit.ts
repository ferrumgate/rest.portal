
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

// check if config changed
let lastConfigServiceUpdateTime = '';
export async function passportInit(req: any, res: any, next: any) {

    const configService = (req.appService as AppService).configService;
    if (configService.lastUpdateTime != lastConfigServiceUpdateTime) {//if config changed
        const auth = await configService.getAuthSettings();
        const domain = await configService.getDomain();
        const url = await configService.getUrl();

        //init local 
        localInit();
        //init apikey
        apiKeyInit();
        //init jwt verification
        jwtInit();
        // init sessionkey
        tunnelKeyInit();
        // init google
        const oauthGoogle = auth.oauth?.providers.find(x => x.type == 'google');
        if (oauthGoogle) {
            oauthGoogleInit(oauthGoogle, url);
        }
        // init linkedin
        const oauthLinkedin = auth.oauth?.providers.find(x => x.type == 'linkedin');
        if (oauthLinkedin) {
            oauthLinkedinInit(oauthLinkedin, url);
        }
        // init active directory
        const activeDirectory = auth.ldap?.providers.find(x => x.type == 'activedirectory');
        if (activeDirectory) {
            activeDirectoryInit(activeDirectory, url);
        }
        lastConfigServiceUpdateTime = configService.lastUpdateTime;

    }
    next();
}


export async function passportAuthenticate(req: any, res: any, next: any, strategyList: string[]) {
    try {
        //this part must be array, otherwise
        let strategyNames = Array.isArray(strategyList) ? strategyList.flat() : []
        if (!Array.isArray(strategyList) && strategyList) {
            strategyNames.push(strategyList);
        }


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
                            next(error || errors[0]);
                        }


                    }

                }

        })
        auth(req, res, next);
    } catch (err: any) {
        next(err);
    }
}

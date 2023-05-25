
import { localInit, localUnuse } from "./local";
import { apiKeyInit, apiKeyUnuse } from "./apikey";
import { jwtInit, jwtUnuse } from "./jwt";
import { oauthGoogleInit, oauthGoogleUnuse } from "./google";
import { oauthLinkedinInit, oauthLinkedinUnuse } from "./linkedin";
import { AppService } from "../../service/appService";
import { tunnelKeyInit, tunnelKeyUnuse } from "./tunnelKey";
import { activeDirectoryInit, activeDirectoryUnuse } from "./activeDirectory";
import passport from "passport";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../../restfullException";
import { logger } from "../../common";
import { samlAuth0Init, samlAuth0Unuse } from "./auth0Saml";
import { exchangeKeyInit, exchangeKeyUnuse } from "./exchangeKey";
import { certInit, certUnuse } from "./certificate";
import { samlAzureInit, samlAzureUnuse } from "./azureSaml";

// check if config changed
let lastConfigServiceUpdateTime = '';
export const passportConf: { activeStrategies: string[] } = {
    activeStrategies: []
}

export async function passportInit(req: any, res: any, next: any) {

    const configService = (req.appService as AppService).configService;
    if (await configService.getLastUpdateTime() != lastConfigServiceUpdateTime) {//if config changed
        const oauth = await configService.getAuthSettingOAuth();
        const ldap = await configService.getAuthSettingLdap();
        const saml = await configService.getAuthSettingSaml();
        const domain = await configService.getDomain();
        let url = await configService.getUrl();
        const configUrl = new URL(url);

        const protocol = req.protocol + ':';
        if ([protocol != configUrl.protocol]) {
            url = url.replace(configUrl.protocol, protocol);
        }
        logger.info(`passport init url: ` + url);



        let activeStrategies = [];
        //init local 
        localUnuse();
        const local = localInit();
        activeStrategies.push(local);
        //init apikey
        apiKeyUnuse();
        const apikey = apiKeyInit();
        activeStrategies.push(apikey);
        //init jwt verification
        jwtUnuse();
        const jwt = jwtInit();
        activeStrategies.push(jwt);
        // init tunnelKey
        tunnelKeyUnuse();
        const tunnelKey = tunnelKeyInit();
        activeStrategies.push(tunnelKey);

        //init certificate verification
        certUnuse();
        const cert = certInit();
        activeStrategies.push(cert);

        // init exchangeKey
        exchangeKeyUnuse();
        const exchangeKey = exchangeKeyInit();
        activeStrategies.push(exchangeKey);
        // init google
        oauthGoogleUnuse();
        const oauthGoogle = oauth?.providers.find(x => x.type == 'google');
        if (oauthGoogle && oauthGoogle.isEnabled) {
            const google = oauthGoogleInit(oauthGoogle, url);
            activeStrategies.push(google);
        }
        // init linkedin
        oauthLinkedinUnuse()
        const oauthLinkedin = oauth?.providers.find(x => x.type == 'linkedin');
        if (oauthLinkedin && oauthLinkedin.isEnabled) {
            const linkedin = oauthLinkedinInit(oauthLinkedin, url);
            activeStrategies.push(linkedin);
        }
        // init active directory
        activeDirectoryUnuse();
        const activeDirectory = ldap?.providers.find(x => x.type == 'activedirectory');
        if (activeDirectory && activeDirectory.isEnabled) {

            const activedirectory = activeDirectoryInit(activeDirectory, url);
            activeStrategies.push(activedirectory);
        }
        // init auth0 saml
        samlAuth0Unuse();
        const auth0 = saml?.providers.find(x => x.type == 'auth0');
        if (auth0 && auth0.isEnabled) {
            const saml = samlAuth0Init(auth0, url);
            activeStrategies.push(saml);
        }

        // init azure saml
        samlAzureUnuse();
        const azure = saml?.providers.find(x => x.type == 'azure');
        if (azure && azure.isEnabled) {
            const saml = samlAzureInit(azure, url);
            activeStrategies.push(saml);
        }
        passportConf.activeStrategies = activeStrategies;
        lastConfigServiceUpdateTime = await configService.getLastUpdateTime();

    }
    next();
}
export function passportFilterActiveStrategies(methods: string[]) {
    //check according to initted methods;
    return (methods as string[]).filter(x => passportConf.activeStrategies.includes(x));
}


export async function passportAuthenticate(req: any, res: any, next: any, strategyList: string[]) {

    await new Promise((resolve, reject) => {
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
                reject(err);
            else
                if (user)
                    resolve(user);
                else {
                    if (!Array.isArray(info))
                        info = [info];
                    let results = (info as any[]);
                    if (!results.length)
                        reject(new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrAuthMethodNotFound, 'no method'));
                    else {
                        const errors = results.filter(y => y);
                        const success = results.filter(y => !y);
                        if (success.length)
                            resolve('');
                        else {
                            const error = errors.find(x => x instanceof RestfullException);
                            reject(error || new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrAuthMethodNoSuccess, 'no success'));
                        }
                    }
                }
        })
        auth(req, res, next);
    })
    next();

}



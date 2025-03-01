import passport from "passport";
import { logger } from "../../common";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../../restfullException";
import { AppService } from "../../service/appService";
import { activeDirectoryInit, activeDirectoryUnuse } from "./activeDirectory";
import { apiKeyInit, apiKeyUnuse } from "./apikey";
import { samlAuth0Init, samlAuth0Unuse } from "./auth0Saml";
import { samlAzureInit, samlAzureUnuse } from "./azureSaml";
import { certInit, certUnuse } from "./certificate";
import { exchangeKeyInit, exchangeKeyUnuse } from "./exchangeKey";
import { oauthGoogleInit, oauthGoogleUnuse } from "./google";
import { jwtInit, jwtUnuse } from "./jwt";
import { oauthLinkedinInit, oauthLinkedinUnuse } from "./linkedin";
import { localInit, localUnuse } from "./local";
import { openIdInit, openIdUnuse } from "./openId";
import { radiusInit, radiusUnuse } from "./radius";
import { tunnelKeyInit, tunnelKeyUnuse } from "./tunnelKey";

// check if config changed
let lastConfigServiceUpdateTime = '';
export const passportConf: { activeStrategies: string[] } = {
    activeStrategies: []
}
async function executeTryCatch(func: any) {
    try {
        await func();
    } catch (ignore) {
        logger.error(ignore);
    }
}

export async function passportInit(req: any, res: any, next: any) {

    const configService = (req.appService as AppService).configService;

    if (await configService.getLastUpdateTime() != lastConfigServiceUpdateTime) {//if config changed
        const oauth = await configService.getAuthSettingOAuth();
        const ldap = await configService.getAuthSettingLdap();
        const saml = await configService.getAuthSettingSaml();
        const openId = await configService.getAuthSettingOpenId();
        const radius = await configService.getAuthSettingRadius();
        const domain = await configService.getDomain();
        let url = await configService.getUrl();
        const configUrl = new URL(url);

        const protocol = req.protocol + ':';
        if (protocol != configUrl.protocol) {
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
            await executeTryCatch(async () => {
                const google = oauthGoogleInit(oauthGoogle, url);
                activeStrategies.push(google);
            })
        }

        // init linkedin

        oauthLinkedinUnuse()
        const oauthLinkedin = oauth?.providers.find(x => x.type == 'linkedin');
        if (oauthLinkedin && oauthLinkedin.isEnabled) {
            await executeTryCatch(async () => {
                const linkedin = oauthLinkedinInit(oauthLinkedin, url);
                activeStrategies.push(linkedin);
            })
        }


        // init active directory

        activeDirectoryUnuse();
        const activeDirectory = ldap?.providers.find(x => x.type == 'activedirectory');
        if (activeDirectory && activeDirectory.isEnabled) {
            await executeTryCatch(async () => {
                const activedirectory = activeDirectoryInit(activeDirectory, url);
                activeStrategies.push(activedirectory);
            })
        }

        // init auth0 saml

        samlAuth0Unuse();
        const auth0 = saml?.providers.find(x => x.type == 'auth0');
        if (auth0 && auth0.isEnabled) {
            await executeTryCatch(async () => {
                const saml = samlAuth0Init(auth0, url);
                activeStrategies.push(saml);
            })
        }


        // init azure saml
        samlAzureUnuse();
        const azure = saml?.providers.find(x => x.type == 'azure');
        if (azure && azure.isEnabled) {
            await executeTryCatch(async () => {
                const saml = samlAzureInit(azure, url);
                activeStrategies.push(saml);
            })
        }

        // init  radius
        radiusUnuse();
        const radiusProvider = radius?.providers.find(x => x.baseType == 'radius');
        if (radiusProvider && radiusProvider.isEnabled) {
            await executeTryCatch(async () => {
                const radiusStrategy = radiusInit(radiusProvider);
                activeStrategies.push(radiusStrategy);
            })
        }


        // openId generic 
        const openIds = openId?.providers.filter(x => x.type == 'generic');
        if (openIds) {
            for (const item of openIds) {
                await executeTryCatch(async () => {
                    if (item.authName) {

                        openIdUnuse(item.authName || '');
                        if (item.isEnabled) {
                            const openId = await openIdInit(item, url);
                            activeStrategies.push(openId);
                        }
                    }
                })
            }

        }

        /*  // oauth2 generic 
         const oauth2 = oauth?.providers.filter(x => x.type == 'generic');
         if (oauth2) {
             for (const item of oauth2) {
                 await executeTryCatch(async () => {
                     if (item.authName) {
 
                         oauth2Unuse(item.authName);
                         if (item.isEnabled) {
                             const oauth2Name = await oauth2Init(item, url);
                             activeStrategies.push(oauth2Name);
                         }
                     }
                 })
             }
         } */


        passportConf.activeStrategies = activeStrategies;
        lastConfigServiceUpdateTime = await configService.getLastUpdateTime();

    }


    next();
}
export function passportFilterActiveStrategies(methods: string[]) {
    //check according to initted methods;
    return (methods as string[]).filter(x => passportConf.activeStrategies.includes(x));
}



export async function passportAuthenticateFromReqProviderName(req: any, res: any, next: any) {
    if (!req.params.providerName)
        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, ErrorCodesInternal.ErrAuthMethodNotFound, 'no method')
    await passportAuthenticate(req, res, next, [req.params.providerName])
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
        const auth = passport.authenticate(strategyNames, { session: false, passReqToCallback: true }, async (err: any, user: any, info: any, status: any) => {

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



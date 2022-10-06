
import { localInit } from "./local";
import { apiKeyInit } from "./apikey";
import { jwtInit } from "./jwt";
import { oauthGoogleInit } from "./google";
import { oauthLinkedinInit } from "./linkedin";
import { AppService } from "../../service/appService";
import { tunnelKeyInit } from "./tunnelKey";
import { activeDirectoryInit } from "./activeDirectory";

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

import { localInit } from "./local";
import { apiKeyInit } from "./apikey";
import { jwtInit } from "./jwt";
import { googleInit } from "./google";
import { linkedinInit } from "./linkedin";
import { AppService } from "../../service/appService";
import { tunnelKeyInit } from "./tunnelKey";

// check if config changed
let lastConfigServiceUpdateTime = '';
export async function passportInit(req: any, res: any, next: any) {

    const configService = (req.appService as AppService).configService;
    if (configService.lastUpdateTime != lastConfigServiceUpdateTime) {//if config changed
        const auth = await configService.getAuthOption();
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
        if (auth.google) {
            googleInit(auth, url);
        }
        // init linkedin
        if (auth.linkedin) {
            linkedinInit(auth, url);
        }
        lastConfigServiceUpdateTime = configService.lastUpdateTime;

    }
    next();
}
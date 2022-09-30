import { assert } from "console";
import { routerAuth } from "./api/authApi";
import { routerConfig } from "./api/configApi";
import { routerRegister } from "./api/registerApi";
import { routerUserAuthenticated, routerUserEmailConfirm, routerUserForgotPassword, routerUserResetPassword } from "./api/userApi";
import { asyncHandler, asyncHandlerWithArgs, globalErrorHandler, logger } from "./common";
import { ErrorCodes, RestfullException } from "./restfullException";
import { AppService } from "./service/appService";
import { Util } from "./util";
import * as helmet from 'helmet';
import cors from 'cors';
import { corsOptionsDelegate } from "./api/cors";
import { routerClientTunnelAuthenticated } from "./api/clientApi";
import fs from "fs";
import { routerConfigureAuthenticated } from "./api/configureApi";
import { routerNetworkAuthenticated } from "./api/ networkApi";
import { routerGatewayAuthenticated } from "./api/gatewayApi";


const bodyParser = require('body-parser');
const express = require('express');


const port = Number(process.env.PORT) | 8080;


//express app
export const app = express();
app.use(express.static('dassets'));
app.appService = new AppService();

//disable powerer by
//app.disable('x-powered-by');

app.use(helmet.default());




const setAppService = async (req: any, res: any, next: any) => {
    req.appService = app.appService;//important
    next();
};

const rateLimit = async (req: any, res: any, next: any, ...args: any) => {
    const appService = req.appService as AppService;
    await appService.rateLimit.check(req.clientIp, args[0][0], args[0][1]);
    next();
};
const checkCaptcha = async (req: any, res: any, next: any, ...args: any) => {
    const appService = req.appService as AppService;
    if (req.body.captcha) {
        await appService.captchaService.check(req.body.captcha, req.body.action);
        // TODO delete ratelimit 
        // await appService.rateLimit.delete(req.clientIp, args[0][0], args[0][1]);
    } else
        if (req.query.captcha) {
            await appService.captchaService.check(req.query.captcha, req.query.action);
            // TODO delete ratelimit 
            // await appService.rateLimit.delete(req.clientIp, args[0][0], args[0][1]);
        } else {
            try {
                await appService.rateLimit.check(req.clientIp, args[0][0], args[0][1]);
            } catch (err: any) {
                // TODO check here if captcha key exists
                // otherwise dont check captcha

                throw new RestfullException(428, ErrorCodes.ErrCaptchaRequired, 'captcha required');
            }
        }
    next();
};
const findClientIp = async (req: any, res: any, next: any) => {
    req.clientIp = Util.findClientIpAddress(req);
    req.baseHost = Util.findHttpProtocol(req) + '://' + Util.findHttpHost(req);
    next();
}


const noAuthentication = (req: any, res: any, next: any) => {
    next();
};

//metrics
//app.use(metricsMiddleware);
//middlewares
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));




app.use("(\/api)?/test",
    asyncHandler(cors(corsOptionsDelegate)),
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'test', 2),
    asyncHandler(async (req: any, res: any, next: any) => {
        assert(req.appService);
        res.status(200).json({ result: "ok", clientIp: req.clientIp });
    }));


app.use('(\/api)?/register',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'register', 100),
    asyncHandlerWithArgs(rateLimit, 'registerHourly', 1000),
    asyncHandlerWithArgs(rateLimit, 'registerDaily', 10000),
    asyncHandlerWithArgs(checkCaptcha, 'registerCaptcha', 5),
    asyncHandler(noAuthentication),
    routerRegister);


app.use('(\/api)?/user/confirmemail',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'userConfirm', 100),
    asyncHandlerWithArgs(rateLimit, 'userConfirmHourly', 1000),
    asyncHandlerWithArgs(rateLimit, 'userConfirmDaily', 10000),
    asyncHandlerWithArgs(checkCaptcha, 'userConfirmCaptcha', 5),
    asyncHandler(noAuthentication),
    routerUserEmailConfirm);


app.use('(\/api)?/user/forgotpass',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'userForgotPass', 100),
    asyncHandlerWithArgs(rateLimit, 'userForgotPassHourly', 1000),
    asyncHandlerWithArgs(rateLimit, 'userForgotPassDaily', 10000),
    asyncHandlerWithArgs(checkCaptcha, 'userForgotPassCaptcha', 5),
    asyncHandler(noAuthentication),
    routerUserForgotPassword);

app.use('(\/api)?/user/resetpass',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'userResetPass', 100),
    asyncHandlerWithArgs(rateLimit, 'userResetPassHourly', 1000),
    asyncHandlerWithArgs(rateLimit, 'userResetPassDaily', 10000),
    asyncHandlerWithArgs(checkCaptcha, 'userResetPassCaptcha', 5),
    asyncHandler(noAuthentication),
    routerUserResetPassword);


app.use('(\/api)?/user',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'user', 1000),
    asyncHandlerWithArgs(rateLimit, 'userHourly', 10000),
    asyncHandlerWithArgs(rateLimit, 'userDaily', 50000),
    routerUserAuthenticated);


app.use('(\/api)?/auth',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'auth', 250),
    asyncHandlerWithArgs(rateLimit, 'authHourly', 1000),
    asyncHandlerWithArgs(rateLimit, 'authDaily', 20000),
    asyncHandlerWithArgs(checkCaptcha, 'authCaptcha', 500),
    asyncHandler(noAuthentication),
    routerAuth);


app.use('(\/api)?/config/public',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'configPublic', 100),
    asyncHandlerWithArgs(rateLimit, 'configPublicHourly', 1000),
    asyncHandlerWithArgs(rateLimit, 'configPublicDaily', 10000),
    asyncHandler(noAuthentication),
    routerConfig);






app.use('(\/api)?/client/tunnel',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'clientTunnel', 100),
    asyncHandlerWithArgs(rateLimit, 'clientTunnelHourly', 1000),
    asyncHandlerWithArgs(rateLimit, 'clientTunnelDaily', 10000),
    routerClientTunnelAuthenticated);


app.use('(\/api)?/configure',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'configure', 100),
    asyncHandlerWithArgs(rateLimit, 'configureHourly', 1000),
    asyncHandlerWithArgs(rateLimit, 'configureDaily', 5000),
    asyncHandlerWithArgs(checkCaptcha, 'configureCaptcha', 50),
    routerConfigureAuthenticated);


app.use('(\/api)?/network',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'network', 1000),
    asyncHandlerWithArgs(rateLimit, 'networkHourly', 1000),
    asyncHandlerWithArgs(rateLimit, 'networkDaily', 5000),
    asyncHandlerWithArgs(checkCaptcha, 'networkCaptcha', 50),
    routerNetworkAuthenticated);


app.use('(\/api)?/gateway',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(rateLimit, 'gateway', 1000),
    asyncHandlerWithArgs(rateLimit, 'gatewayHourly', 1000),
    asyncHandlerWithArgs(rateLimit, 'gatewayDaily', 5000),
    asyncHandlerWithArgs(checkCaptcha, 'gatewayCaptcha', 50),
    routerGatewayAuthenticated);








/**
 *  @abstract global error handler middleware
 */
app.use(globalErrorHandler);


app.start = async function () {
    //create new jwt certificates

    await Util.createSelfSignedCrt("ferrumgate.com");
    (app.appService as AppService).configService.setJWTSSLCertificate({
        privateKey: fs.readFileSync('./ferrumgate.com.key').toString('utf-8'),
        publicKey: fs.readFileSync('./ferrumgate.com.crt').toString('utf-8'),
    })


    app.listen(port, () => {
        logger.info('service started on ', port);
    })
}

app.start();






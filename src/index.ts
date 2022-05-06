import { assert } from "console";
import { routerRegister } from "./api/registerApi";
import { routerUserConfirm, routerUserForgotPassword, routerUserResetPassword } from "./api/userApi";
import { asyncHandler, asyncHandlerWithArgs, globalErrorHandler, logger } from "./common";
import { ErrorCodes, RestfullException } from "./restfullException";
import { AppService } from "./service/appService";
import { Util } from "./util";



const bodyParser = require('body-parser');
const express = require('express');


const port = Number(process.env.PORT) | 8080;


//express app
export const app = express();
app.use(express.static('dassets'))
app.appService = new AppService();

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
        await appService.captchaService.check(req.body.captcha);
    } else {
        try {
            await appService.rateLimit.check(req.clientIp, args[0][0], args[0][1]);
        } catch (err: any) {
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


app.setAuthMethodsNone = (req: any, res: any, next: any) => {
    next();
};

//metrics
//app.use(metricsMiddleware);
//middlewares
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));



app.use("(\/api)?/test",
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
    asyncHandlerWithArgs(checkCaptcha, 'registerCaptcha', 5),
    asyncHandlerWithArgs(rateLimit, 'register', 10),
    asyncHandlerWithArgs(rateLimit, 'registerHourly', 100),
    asyncHandlerWithArgs(rateLimit, 'registerDay', 1000),
    asyncHandler(app.setAuthMethodsNone),
    routerRegister);


app.use('(\/api)?/user/confirm',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(checkCaptcha, 'userConfirmCaptcha', 5),
    asyncHandlerWithArgs(rateLimit, 'userConfirm', 10),
    asyncHandlerWithArgs(rateLimit, 'userConfirmHourly', 100),
    asyncHandlerWithArgs(rateLimit, 'userConfirmDay', 1000),
    asyncHandler(app.setAuthMethodsNone),
    routerUserConfirm);


app.use('(\/api)?/user/forgotpass',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(checkCaptcha, 'userForgotPassCaptcha', 5),
    asyncHandlerWithArgs(rateLimit, 'userForgotPass', 10),
    asyncHandlerWithArgs(rateLimit, 'userForgotPassHourly', 100),
    asyncHandlerWithArgs(rateLimit, 'userForgotPassDay', 1000),
    asyncHandler(app.setAuthMethodsNone),
    routerUserForgotPassword);

app.use('(\/api)?/user/resetpass',
    asyncHandler(setAppService),
    asyncHandler(findClientIp),
    asyncHandlerWithArgs(checkCaptcha, 'userResetPassCaptcha', 5),
    asyncHandlerWithArgs(rateLimit, 'userResetPass', 10),
    asyncHandlerWithArgs(rateLimit, 'userResetPassHourly', 100),
    asyncHandlerWithArgs(rateLimit, 'userResetPassDay', 1000),
    asyncHandler(app.setAuthMethodsNone),
    routerUserResetPassword);






/**
 *  @abstract global error handler middleware
 */
app.use(globalErrorHandler);


app.start = function () {

    app.listen(port, () => {
        logger.info('service started on ', port);
    })
}

app.start();






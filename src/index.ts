import { assert } from "console";
import { routerAuth } from "./api/authApi";
import { routerConfig, routerConfigAuthenticated } from "./api/configApi";
import { routerRegister } from "./api/registerApi";
import { routerUserAuthenticated, routerUserEmailConfirm, routerUserForgotPassword, routerUserResetPassword } from "./api/userApi";
import { asyncHandler, asyncHandlerWithArgs, checkLimitedMode, globalErrorHandler, logger } from "./common";
import { ErrorCodes, RestfullException } from "./restfullException";
import { AppService, AppSystemService } from "./service/appService";
import { Util } from "./util";
import * as helmet from 'helmet';
import cors from 'cors';
import http from 'http';
import https from 'https';

import { corsOptionsDelegate } from "./api/cors";
import { routerClientTunnelAuthenticated } from "./api/clientApi";
import fs from "fs";
import { routerConfigureAuthenticated } from "./api/configureApi";
import { routerNetworkAuthenticated } from "./api/ networkApi";
import { routerGatewayAuthenticated } from "./api/gatewayApi";
import { routerConfigAuthAuthenticated } from "./api/configAuthApi";
import { passportAuthenticate, passportInit } from "./api/auth/passportInit";
import { routerGroupAuthenticated } from "./api/groupApi";
import { routerServiceAuthenticated } from "./api/serviceApi";
import { routerAuthenticationPolicyAuthenticated, routerAuthorizationPolicyAuthenticated } from "./api/policyApi";
import { routerAuditAuthenticated } from "./api/auditApi";
import { ESService } from "./service/esService";
import { routerActivityAuthenticated } from "./api/activityApi";
import { ConfigService } from "./service/configService";
import { routerSummaryAuthenticated } from "./api/summaryApi";
import { saveActivityError } from "./api/auth/commonAuth";
import { routerIpIntelligenceAuthenticated } from "./api/ipIntelligenceApi";
import { routerDataAuthenticated } from "./api/dataApi";
import { routerPKIAuthenticated } from "./api/pkiApi";
import path from "path";


const bodyParser = require('body-parser');
const express = require('express');


const port = Number(process.env.PORT) | 8181;
const ports = Number(process.env.PORTS) | 8443;

export class ExpressApp {
    app: any;
    httpServer: any;
    httpsServer: any;
    appService: AppService;
    appSystemService: AppSystemService;
    //bridge between appService and this parent class
    static https = {
        start: async () => {

        }

    }
    constructor() {
        this.app = express();
        this.appService = new AppService();
        this.appSystemService = new AppSystemService(this.appService);
        this.app.appService = this.appService;
        ExpressApp.https.start = async () => {
            await this.startHttps();
        }
    }
    async init() {


        //express app

        //this.app.use(express.static('dassets'));



        //disable powerer by
        //app.disable('x-powered-by');

        this.app.use(helmet.default());
        //this.app.use(express.static(process.env.STATIC_FOLDER || path.join(__dirname, '../', 'web')))



        const setAppService = async (req: any, res: any, next: any) => {
            req.appService = this.appService;//important
            next();
        };

        const rateLimit = async (req: any, res: any, next: any, ...args: any) => {
            try {
                const appService = req.appService as AppService;
                await appService.rateLimit.check(req.clientIp, args[0][0], args[0][1]);
                next();
            } catch (err) {
                await saveActivityError(req, 'ratelimit', err, (log) => {
                    log.statusMessageDetail = args[0][0];
                });
                throw err;
            }

        };
        const checkCaptcha = async (req: any, res: any, next: any, ...args: any) => {
            try {
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const captcha = await configService.getCaptcha();
                const captchaIsOK = captcha.client && captcha.server;
                if (captchaIsOK) {
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

                                throw new RestfullException(428, ErrorCodes.ErrCaptchaRequired, ErrorCodes.ErrCaptchaRequired, 'captcha required');
                            }
                        }
                } else {
                    //no captcha settings
                    logger.warn(`captcha settings is empty, please fill it`);
                }
                next();
            } catch (err) {
                saveActivityError(req, "captcha", err);
                throw err;
            }
        };
        const findClientIp = async (req: any, res: any, next: any) => {
            req.clientIp = Util.findClientIpAddress(req);
            req.baseHost = Util.findHttpProtocol(req) + '://' + Util.findHttpHost(req);
            next();
        }


        const noAuthentication = async (req: any, res: any, next: any) => {
            next();
        };






        //metrics
        //this.app.use(metricsMiddleware);
        //middlewares
        this.app.use(bodyParser.json({ limit: '50mb' }));
        this.app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));





        this.app.use("(\/api)?/test/activedirectory",
            asyncHandler(cors(corsOptionsDelegate)),
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'test', 200),
            asyncHandler(passportInit),
            asyncHandler(async (req: any, res: any, next: any) => {
                req.body.username = 'hamza';
                req.body.password = 'Qa12345678'
                next();
            }),
            //asyncHandlerWithArgs(passportAuthenticate, []),//internal error gives

            asyncHandlerWithArgs(passportAuthenticate, ['activedirectory']),
            //asyncHandlerWithArgs(passportAuthenticate, ['headerapikey', 'local']),
            //asyncHandlerWithArgs(passportAuthenticate, ['headerapikey', 'local', 'activedirectory']),

            asyncHandler(async (req: any, res: any, next: any) => {
                assert(req.appService);
                res.status(200).json({ result: "ok", clientIp: req.clientIp });
            }));
        this.app.use("(\/api)?/test",
            asyncHandler(cors(corsOptionsDelegate)),
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'test', 2),
            asyncHandlerWithArgs(checkLimitedMode, 'DELETE', 'PUT'),
            asyncHandler(async (req: any, res: any, next: any) => {
                assert(req.appService);
                res.status(200).json({ result: "ok", clientIp: req.clientIp });
            }));


        this.app.use('(\/api)?/register',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'register', 100),
            asyncHandlerWithArgs(rateLimit, 'registerHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'registerDaily', 10000),
            asyncHandlerWithArgs(checkCaptcha, 'registerCaptcha', 5),
            asyncHandlerWithArgs(checkLimitedMode),
            asyncHandler(noAuthentication),
            routerRegister);


        this.app.use('(\/api)?/user/confirmemail',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'userConfirm', 100),
            asyncHandlerWithArgs(rateLimit, 'userConfirmHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'userConfirmDaily', 10000),
            asyncHandlerWithArgs(checkCaptcha, 'userConfirmCaptcha', 5),
            asyncHandlerWithArgs(checkLimitedMode),
            asyncHandler(noAuthentication),
            routerUserEmailConfirm);


        this.app.use('(\/api)?/user/forgotpass',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'userForgotPass', 100),
            asyncHandlerWithArgs(rateLimit, 'userForgotPassHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'userForgotPassDaily', 10000),
            asyncHandlerWithArgs(checkCaptcha, 'userForgotPassCaptcha', 5),
            asyncHandlerWithArgs(checkLimitedMode),
            asyncHandler(noAuthentication),
            routerUserForgotPassword);

        this.app.use('(\/api)?/user/resetpass',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'userResetPass', 100),
            asyncHandlerWithArgs(rateLimit, 'userResetPassHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'userResetPassDaily', 10000),
            asyncHandlerWithArgs(checkCaptcha, 'userResetPassCaptcha', 5),
            asyncHandlerWithArgs(checkLimitedMode),
            asyncHandler(noAuthentication),
            routerUserResetPassword);


        this.app.use('(\/api)?/user',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'user', 1000),
            asyncHandlerWithArgs(rateLimit, 'userHourly', 10000),
            asyncHandlerWithArgs(rateLimit, 'userDaily', 50000),
            asyncHandlerWithArgs(checkCaptcha, 'userCaptcha', 500),
            asyncHandlerWithArgs(checkLimitedMode, 'DELETE', 'POST'),
            routerUserAuthenticated);


        this.app.use('(\/api)?/auth',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'auth', 250),
            asyncHandlerWithArgs(rateLimit, 'authHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'authDaily', 20000),
            asyncHandlerWithArgs(checkCaptcha, 'authCaptcha', 500),
            asyncHandler(noAuthentication),
            routerAuth);


        this.app.use('(\/api)?/config/public',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'configPublic', 100),
            asyncHandlerWithArgs(rateLimit, 'configPublicHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'configPublicDaily', 10000),
            //asyncHandlerWithArgs(checkCaptcha, 'configPublic', 1000),//specialy disabled
            asyncHandler(noAuthentication),
            routerConfig);

        this.app.use('(\/api)?/config/auth',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'config', 100),
            asyncHandlerWithArgs(rateLimit, 'configHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'configDaily', 10000),
            asyncHandlerWithArgs(checkCaptcha, 'config', 50),
            asyncHandlerWithArgs(checkLimitedMode, 'GET', 'POST', 'PUT', 'DELETE'),
            asyncHandler(noAuthentication),
            routerConfigAuthAuthenticated);


        this.app.use('(\/api)?/config',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'config', 100),
            asyncHandlerWithArgs(rateLimit, 'configHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'configDaily', 10000),
            asyncHandlerWithArgs(checkCaptcha, 'config', 50),
            asyncHandlerWithArgs(checkLimitedMode, 'GET', 'POST', 'PUT', 'DELETE'),
            asyncHandler(noAuthentication),
            routerConfigAuthenticated);






        this.app.use('(\/api)?/client/tunnel',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'clientTunnel', 100),
            asyncHandlerWithArgs(rateLimit, 'clientTunnelHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'clientTunnelDaily', 10000),
            asyncHandlerWithArgs(checkCaptcha, 'clientTunnelCaptcha', 100),
            routerClientTunnelAuthenticated);


        this.app.use('(\/api)?/configure',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'configure', 100),
            asyncHandlerWithArgs(rateLimit, 'configureHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'configureDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'configureCaptcha', 50),
            routerConfigureAuthenticated);


        this.app.use('(\/api)?/network',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'network', 1000),
            asyncHandlerWithArgs(rateLimit, 'networkHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'networkDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'networkCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode, 'POST', 'PUT', 'DELETE'),
            routerNetworkAuthenticated);


        this.app.use('(\/api)?/gateway',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'gateway', 1000),
            asyncHandlerWithArgs(rateLimit, 'gatewayHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'gatewayDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'gatewayCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode, 'POST', 'PUT', 'DELETE'),
            routerGatewayAuthenticated);

        this.app.use('(\/api)?/group',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'group', 1000),
            asyncHandlerWithArgs(rateLimit, 'groupHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'groupDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'groupCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode, 'POST', 'PUT', 'DELETE'),
            routerGroupAuthenticated);


        this.app.use('(\/api)?/service',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'service', 1000),
            asyncHandlerWithArgs(rateLimit, 'serviceHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'serviceDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'serviceCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode, 'POST', 'PUT', 'DELETE'),
            routerServiceAuthenticated);


        this.app.use('(\/api)?/policy/authn',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'policyAuthn', 1000),
            asyncHandlerWithArgs(rateLimit, 'policyAuthnHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'policyAuthnDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'policyAuthnCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode, 'POST', 'PUT', 'DELETE'),
            routerAuthenticationPolicyAuthenticated);


        this.app.use('(\/api)?/policy/authz',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'policyAuthz', 1000),
            asyncHandlerWithArgs(rateLimit, 'policyAuthzHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'policyAuthzDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'policyAuthzCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode, 'POST', 'PUT', 'DELETE'),
            routerAuthorizationPolicyAuthenticated);

        this.app.use('(\/api)?/log/audit',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'logsAudit', 1000),
            asyncHandlerWithArgs(rateLimit, 'logsAuditHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'logsAuditDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'logsAuditCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode),
            routerAuditAuthenticated);

        this.app.use('(\/api)?/insight/activity',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'insightActivity', 1000),
            asyncHandlerWithArgs(rateLimit, 'insightActivityHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'insightActivityDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'insightActivityCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode),
            routerActivityAuthenticated);


        this.app.use('(\/api)?/summary',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'summary', 1000),
            asyncHandlerWithArgs(rateLimit, 'summaryHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'summaryDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'summaryCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode),
            routerSummaryAuthenticated);


        this.app.use('(\/api)?/data',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'data', 1000),
            asyncHandlerWithArgs(rateLimit, 'dataHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'dataDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'dataCaptcha', 50),
            routerDataAuthenticated);

        this.app.use('(\/api)?/ip/intelligence',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'ipIntelligence', 1000),
            asyncHandlerWithArgs(rateLimit, 'ipIntelligenceHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'ipIntelligenceDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'ipIntelligenceCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode, 'POST', 'PUT', 'DELETE'),
            routerIpIntelligenceAuthenticated);

        this.app.use('(\/api)?/pki',
            asyncHandler(setAppService),
            asyncHandler(findClientIp),
            asyncHandlerWithArgs(rateLimit, 'pki', 1000),
            asyncHandlerWithArgs(rateLimit, 'pkiHourly', 1000),
            asyncHandlerWithArgs(rateLimit, 'pkiDaily', 5000),
            asyncHandlerWithArgs(checkCaptcha, 'pkiCaptcha', 50),
            asyncHandlerWithArgs(checkLimitedMode, 'POST', 'PUT', 'DELETE'),
            routerPKIAuthenticated);



        this.app.use(express.static(process.env.STATIC_FOLDER || path.join(__dirname, '../', 'web')))


        /**
         *  @abstract global error handler middleware
         */
        this.app.use(globalErrorHandler);



    }
    async start() {
        await this.init();

        if (!process.env.NODE_TEST) {
            await this.appService.start();

        }


        if (!process.env.NODE_TEST)
            try {
                await this.appService.esService.auditCreateIndexIfNotExits({} as any);
            } catch (err) { logger.error(err); }

        if (!process.env.NODE_TEST)
            await this.appSystemService.start();

        await this.startHttp();

    }
    async startHttp() {
        if (this.httpServer)
            this.httpServer.close();
        this.httpServer = null;
        this.httpServer = http.createServer(this.app);
        this.httpServer.listen(port, () => {
            logger.info('service started on ', port);
        })
    }
    async stopHttp() {
        if (this.httpServer)
            this.httpServer.close();
        this.httpServer = null;
    }
    httpsHash = '';
    async startHttps() {
        const ca = await this.appService.configService.getCASSLCertificate();
        const int = (await this.appService.configService.getInSSLCertificateAll()).find(x => x.category == 'tls');
        const web = await this.appService.configService.getWebSSLCertificateSensitive();
        if (web.publicCrt && web.privateKey) {
            let hash = Util.sha256(web.publicCrt + web.privateKey);
            if (hash != this.httpsHash) {//if changed
                if (this.httpsServer)
                    this.httpsServer.close();
                this.httpsServer = null;
                fs.writeFileSync('/tmp/web.cert', web.publicCrt || '');
                fs.writeFileSync('/tmp/in.cert', int?.publicCrt || '');
                fs.writeFileSync('/tmp/ca.cert', ca.publicCrt || '');
                this.httpsServer = https.createServer({ cert: web.publicCrt, key: web.privateKey }, this.app);
                this.httpsServer.listen(ports, () => {
                    logger.info('service ssl started on ', ports);
                })
                this.httpsHash = hash;
            }
        }

    }
    async stopHttps() {
        if (this.httpsServer)
            this.httpsServer.close();
        this.httpsServer = null;
    }
    async stop() {
        await this.stopHttp();
        await this.stopHttps();
    }
}



if (!process.env.NODE_TEST) {
    const app = new ExpressApp();
    app.start().catch(err => {
        logger.error(err);
        process.exit(1);
    })
}








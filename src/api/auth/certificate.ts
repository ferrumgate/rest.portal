import passport from 'passport';
import passportCustom from 'passport-custom';
import { logger } from '../../common';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../../restfullException';
import { AppService } from '../../service/appService';
import { HelperService } from '../../service/helperService';
import { UtilPKI } from '../../utilPKI';
import { attachActivitySource, attachActivityUser, attachActivityUsername, saveActivity, saveActivityError } from './commonAuth';

const name = 'headercert';
export function certInit() {
    passport.use(name, new passportCustom.Strategy(
        async (req: any, done: any) => {

            try {

                attachActivitySource(req, name);
                let certb64 = req.get('Cert') as string;
                logger.info(`passport local with cert: ${certb64.substring(0, 10)}`);
                const appService = req.appService as AppService;
                const configService = appService.configService;
                const redisService = appService.redisService;
                const sessionService = appService.sessionService;
                const pkiService = appService.pkiService;

                if (!certb64)
                    throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "bad argument");
                const cert = Buffer.from(certb64, 'base64').toString();

                const isValidCert = await pkiService.authVerify(cert);
                if (!isValidCert) {
                    throw new RestfullException(401, ErrorCodes.ErrCertificateVerifyFailed, ErrorCodesInternal.ErrCertificateVerifyFailed, 'cert is not valid');
                }
                const crt = (await UtilPKI.parseCertificate(cert))[0];
                const subject = await UtilPKI.parseSubject(crt);
                const userId = subject['CN'];

                //const user = await configService.getUserByApiKey(apikey);
                const user = await configService.getUserById(userId);


                attachActivityUser(req, user);
                attachActivityUsername(req, user?.username);
                HelperService.isValidUser(user);

                //set user to request object
                req.currentUser = user;

                // TODO we need session
                if (user)
                    req.currentSession = await sessionService.createFakeSession(user, false, req.clientIp, name);

                await saveActivity(req, 'login try');
                return done(null, user);

            } catch (err) {
                await saveActivityError(req, 'login try', err);
                return done(null, null, err);
            }

        }
    ));
    return name;
}

export function certUnuse() {
    return passport.unuse(name);
}
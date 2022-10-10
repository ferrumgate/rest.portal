import passportCustom from 'passport-custom';
import passport from 'passport';
import passportlocal from 'passport-local';
import passportgoogle from 'passport-google-oauth2';
import { AuthSettings } from '../../model/authSettings';
import { logger } from '../../common';
import { AppService } from '../../service/appService';
import { User } from '../../model/user';
import { Util } from '../../util';
import { ErrorCodes, RestfullException } from '../../restfullException';
import { HelperService } from '../../service/helperService';


export function jwtInit() {
    passport.use('jwt', new passportCustom.Strategy(
        async (req: any, done: any) => {
            try {

                const appService = req.appService as AppService;
                const configService = appService.configService;
                const oauth2Service = appService.oauth2Service;

                let authorizationHeader = req.get('Authorization') as string;
                if (!authorizationHeader)
                    throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, 'jwt header not found');
                if (authorizationHeader.indexOf("Bearer") < 0)
                    throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, 'jwt header not found');
                authorizationHeader = authorizationHeader.replace('Bearer', '').trim();

                const token = await oauth2Service.getAccessToken(authorizationHeader);
                if (!token)
                    throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, 'jwt header not found');

                const userId = token.user.id;


                const user = await configService.getUserById(userId);
                HelperService.isValidUser(user);
                //set user to request object
                req.currentUser = user;
                return done(null, user);

            } catch (err) {
                return done(null, null, err);
            }

        }
    ));
}
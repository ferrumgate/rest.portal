import JWT from 'jsonwebtoken';
import OAuth2Server from 'oauth2-server';
import { logger } from '../common';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../restfullException';
import { ConfigService } from './configService';
import { HelperService } from './helperService';
import { SessionService } from './sessionService';


//documentation
//https://oauth2-server.readthedocs.io/en/latest/misc/migrating-v2-to-v3.html#model-specification


export interface Payload {
    expires: number,
    user: any,
    type: string;
}


export const config = {

    JWT_ACCESS_TOKEN_EXPIRY_SECONDS: 5 * 60,
    JWT_REFRESH_TOKEN_EXPIRY_SECONDS: 15 * 60,
    JWT_SING_OPTIONS: { algorithm: 'RS256' } as JWT.SignOptions,
    JWT_VERIFY_OPTIONS: { algorithms: ['RS256'] } as JWT.VerifyOptions,
}

/**
 * @summary OAuth2 implementation refresh_token grant types
 */
export class OAuth2Service implements OAuth2Server.RefreshTokenModel {

    /**
     *
     */
    constructor(private config: ConfigService, private sessionService: SessionService) {


    }

    private generatePayload(type: "access" | "refresh", user: OAuth2Server.User, client: OAuth2Server.Client, timeInMs: number = 0): Payload {
        let expire = new Date();
        if (!timeInMs) {
            expire.setSeconds(expire.getSeconds() + type == 'access' ? config.JWT_ACCESS_TOKEN_EXPIRY_SECONDS : config.JWT_REFRESH_TOKEN_EXPIRY_SECONDS);
        }
        else {
            expire.setMilliseconds(expire.getMilliseconds() + timeInMs);
        }
        let targetUser = { id: user.id, sid: user.sid } as any;

        let payload = {
            expires: expire.getTime(),
            user: targetUser,
            type: type
        }
        return payload;
    }

    private async generateToken(type: "access" | "refresh", user: OAuth2Server.User, client: OAuth2Server.Client, timeInMs: number = 0): Promise<string> {
        let payload = this.generatePayload(type, user, client, timeInMs);

        let secret = (await this.config.getJWTSSLCertificateSensitive()).privateKey || '';
        let token = JWT.sign(payload, secret, config.JWT_SING_OPTIONS);
        return token;
    }
    async generateAccessTokenWithTime(client: OAuth2Server.Client, user: OAuth2Server.User, scope: string | string[], timeInMs: number): Promise<string> {
        logger.info(`generateAccessToken`, JSON.stringify(client), JSON.stringify(user))

        let findUser = await this.config.getUserById(user.id).catch(err => {
            logger.fatal(JSON.stringify(err));
            throw new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodes.ErrInternalError, "internal error");
        })

        if (!findUser)
            throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrUserNotFound, 'unauthorized access');

        let findSession = await this.sessionService.getSession(user.sid).catch(err => {
            logger.fatal(JSON.stringify(err));
            throw new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodesInternal.ErrSessionNotFound, "internal error");
        })

        if (!findSession || findSession.userId != findUser.id)
            throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrSessionInvalid, 'unauthorized access');


        user.id = findUser.id;
        user.sid = user.sid;

        let token = await this.generateToken("access", user, client, timeInMs);

        return token;
    }

    async generateAccessToken(client: OAuth2Server.Client, user: OAuth2Server.User, scope: string | string[]): Promise<string> {

        return await this.generateAccessTokenWithTime(client, user, scope, 0);
    }

    async getAccessToken(accessToken: string): Promise<false | "" | 0 | OAuth2Server.Token | null | undefined> {

        logger.info(`getAccessToken ${accessToken.substring(0, 6)}`)
        let decoded = undefined;
        const publicssl = (await this.config.getJWTSSLCertificate()).publicCrt || '';
        try {
            decoded = JWT.verify(accessToken, publicssl, config.JWT_VERIFY_OPTIONS) as any;

        } catch (err) {
            logger.warn(`jwt verification failed ${accessToken?.substring(0, 6)}`);

            throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, ErrorCodes.ErrJWTVerifyFailed, "jwt verification failed");

        }
        if (decoded.expires <= new Date().getTime())
            throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, ErrorCodes.ErrJWTVerifyFailed, "jwt verification failed");



        if (decoded.type !== 'access')
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrTokenInvalid, "unauthorized access");


        let user = await this.config.getUserById(decoded.user.id).catch(err => {
            logger.fatal(JSON.stringify(err));
            throw new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodes.ErrInternalError, "internal error");
        })

        HelperService.isValidUser(user);


        let session = await this.sessionService.getSession(decoded.user.sid).catch(err => {
            logger.fatal(JSON.stringify(err));
            throw new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodes.ErrInternalError, "internal error");
        })
        if (!session || !user || session.userId != user.id)
            throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrUserSessionNotFoundInvalid, "unauthorized access");




        let token = {
            accessTokenExpiresAt: new Date(decoded.expires),
            user: { id: user?.id, sid: session.id },
            client: decoded.client,
            type: decoded.type,
            accessToken: accessToken
        }


        return (token);

    }

    async generateRefreshTokenWithTime(client: OAuth2Server.Client, user: OAuth2Server.User, scope: string | string[], timeInMs: number): Promise<string> {
        logger.info(`generateRefreshToken  timeInMs: ${timeInMs}`, JSON.stringify(client), JSON.stringify(user));
        let token = await this.generateToken("refresh", user, client, timeInMs);
        return (token);
    }
    async generateRefreshToken(client: OAuth2Server.Client, user: OAuth2Server.User, scope: string | string[]): Promise<string> {
        return await this.generateRefreshTokenWithTime(client, user, scope, 0);
    }

    /**
     * 
     * @param refreshToken 
     * @returns 
     * @remarks be carefull about 
     */
    async getRefreshToken(refreshToken: string): Promise<false | "" | 0 | OAuth2Server.RefreshToken | null | undefined> {
        logger.info(`getRefreshToken ${refreshToken.substring(0, 6)}`);
        let decoded = undefined;

        const publicssl = (await this.config.getJWTSSLCertificate()).publicCrt || '';
        try {
            decoded = JWT.verify(refreshToken, publicssl, config.JWT_VERIFY_OPTIONS) as any;
        } catch (err) {
            logger.warn(`jwt verification failed ${refreshToken}`);
            throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, ErrorCodes.ErrJWTVerifyFailed, "jwt verification failed")
        }
        if (decoded.expires <= new Date().getTime())
            throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, ErrorCodes.ErrJWTVerifyFailed, "jwt verification failed")
        if (decoded.type !== 'refresh')
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrTokenInvalid, "unauthorized access");

        let user = await this.config.getUserById(decoded.user.id).catch(err => {
            logger.fatal(JSON.stringify(err));
            throw new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodes.ErrInternalError, "internal server error");
        })

        HelperService.isValidUser(user);

        let session = await this.sessionService.getSession(decoded.user.sid).catch(err => {
            logger.fatal(JSON.stringify(err));
            throw new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodes.ErrInternalError, "internal error");
        })
        if (!session || !user || session.userId != user.id)
            throw new RestfullException(401, ErrorCodes.ErrNotFound, ErrorCodesInternal.ErrUserSessionNotFoundInvalid, "unauthorized access");

        let token = {
            refreshTokenExpiresAt: new Date(decoded.expires),
            user: { id: user?.id, sid: session.id },
            client: decoded.client,
            type: decoded.type,
            refreshToken: refreshToken
        }
        return (token);

    }



    async getClient(clientId: string, clientSecret: string): Promise<OAuth2Server.Client> {
        logger.info(`getClient method: ${clientId} ${clientSecret}`);
        let client = { id: clientId, clientSecret: clientSecret, grants: ['refresh_token'] };

        return (client);

    }
    async saveToken(token: OAuth2Server.Token, client: OAuth2Server.Client, user: OAuth2Server.User): Promise<false | "" | 0 | OAuth2Server.Token | null | undefined> {
        logger.info(`saveToken method:`, JSON.stringify(token), JSON.stringify(client), JSON.stringify(user));
        return (token);

    }


    async revokeToken(token: OAuth2Server.Token | OAuth2Server.RefreshToken): Promise<boolean> {

        return (true);

    }
    async verifyScope(token: OAuth2Server.Token, scope: string | string[]): Promise<boolean> {

        return (true);

    }







};




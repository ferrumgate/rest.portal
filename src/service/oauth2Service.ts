import OAuth2Server from 'oauth2-server';
import { ConfigService } from './configService';
import JWT from 'jsonwebtoken';
import { logger } from '../common';
import { ErrorCodes, RestfullException } from '../restfullException';
import { HelperService } from './helperService';



//documentation
//https://oauth2-server.readthedocs.io/en/latest/misc/migrating-v2-to-v3.html#model-specification


export interface Payload {
    expires: number,
    user: any,
    type: string;
}


export const config = {

    JWT_TOKEN_EXPIRY_SECONDS: 5 * 60,
    JWT_SING_OPTIONS: { algorithm: 'RS256' } as JWT.SignOptions,
    JWT_VERIFY_OPTIONS: { algorithms: ['RS256'] } as JWT.VerifyOptions,
}

/**
 * OAuth2 implementation refresh_token grant types
 */
export class OAuth2Service implements OAuth2Server.RefreshTokenModel {

    /**
     *
     */
    constructor(private config: ConfigService) {


    }

    private generatePayload(type: "access" | "refresh", user: OAuth2Server.User, client: OAuth2Server.Client): Payload {
        let expire = new Date();
        expire.setSeconds(expire.getSeconds() + type == 'access' ? config.JWT_TOKEN_EXPIRY_SECONDS : config.JWT_TOKEN_EXPIRY_SECONDS * 2);
        let targetUser = { id: user.id } as any;

        let payload = {
            expires: expire.getTime(),
            user: targetUser,
            type: type,

        }
        return payload;
    }

    private async generateToken(type: "access" | "refresh", user: OAuth2Server.User, client: OAuth2Server.Client): Promise<string> {
        let payload = this.generatePayload(type, user, client);

        let secret = (await this.config.getSSLCertificate()).privateKey || '';
        let token = JWT.sign(payload, secret, config.JWT_SING_OPTIONS);
        return token;
    }

    async generateAccessToken(client: OAuth2Server.Client, user: OAuth2Server.User, scope: string | string[]): Promise<string> {
        logger.info(`generateAccessToken`, JSON.stringify(client), JSON.stringify(user))

        let findUser = await this.config.getUserById(user.id).catch(err => {
            logger.fatal(JSON.stringify(err));
            throw new RestfullException(500, ErrorCodes.ErrInternalError, "internal error");
        })

        if (!findUser)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'unauthorized access');

        user.id = findUser.id;

        let token = await this.generateToken("access", user, client);

        return token;

    }

    async getAccessToken(accessToken: string): Promise<false | "" | 0 | OAuth2Server.Token | null | undefined> {

        logger.info(`getAccessToken ${accessToken}`)
        let decoded = undefined;
        const publicssl = (await this.config.getSSLCertificate()).publicKey || '';
        try {
            decoded = JWT.verify(accessToken, publicssl, config.JWT_VERIFY_OPTIONS) as any;

        } catch (err) {
            logger.warn(`jwt verification failed ${accessToken}`);
            throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, "jwt verification failed");

        }
        if (decoded.expires <= new Date().getTime())
            throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, "jwt verification failed");



        if (decoded.type !== 'access')
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, "unauthorized access");


        let user = await this.config.getUserById(decoded.user.id).catch(err => {
            logger.fatal(JSON.stringify(err));
            throw new RestfullException(500, ErrorCodes.ErrInternalError, "internal error");
        })

        HelperService.isValidUser(user);
        let token = {
            accessTokenExpiresAt: new Date(decoded.expires),
            user: { id: user?.id },
            client: decoded.client,
            type: decoded.type,
            accessToken: accessToken


        }


        return (token);

    }

    async generateRefreshToken(client: OAuth2Server.Client, user: OAuth2Server.User, scope: string | string[]): Promise<string> {
        logger.info(`generateRefreshToken `, JSON.stringify(client), JSON.stringify(user));
        let token = await this.generateToken("refresh", user, client);
        return (token);

    }

    /**
     * 
     * @param refreshToken 
     * @returns 
     * @remarks be carefull about 
     */
    async getRefreshToken(refreshToken: string): Promise<false | "" | 0 | OAuth2Server.RefreshToken | null | undefined> {
        logger.info(`getRefreshToken ${refreshToken}`);
        let decoded = undefined;

        const publicssl = (await this.config.getSSLCertificate()).publicKey || '';
        try {
            decoded = JWT.verify(refreshToken, publicssl, config.JWT_VERIFY_OPTIONS) as any;
        } catch (err) {
            logger.warn(`jwt verification failed ${refreshToken}`);
            throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, "jwt verification failed")
        }
        if (decoded.expires <= new Date().getTime())
            throw new RestfullException(401, ErrorCodes.ErrJWTVerifyFailed, "jwt verification failed")
        if (decoded.type !== 'refresh')
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, "unauthorized access");

        let user = await this.config.getUserById(decoded.user.id).catch(err => {
            logger.fatal(JSON.stringify(err));
            throw new RestfullException(500, ErrorCodes.ErrInternalError, "internal server error");
        })

        HelperService.isValidUser(user);

        let token = {
            refreshTokenExpiresAt: new Date(decoded.expires),
            user: { id: user?.id },
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




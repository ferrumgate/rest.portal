
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { InputService } from '../src/service/inputService';
import { RestfullException } from '../src/restfullException';
import { ErrorCodes } from '../src/restfullException';
import { ConfigService } from '../src/service/configService';
import { config, OAuth2Service } from '../src/service/oauth2Service';
import { User } from '../src/model/user';
import OAuth2Server from 'oauth2-server';
import { Util } from '../src/util';



chai.use(chaiHttp);
const expect = chai.expect;




describe('oauth2Service ', async () => {
    const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
    let aUser: User = {
        id: 'someid',
        username: 'hamza.kilic@ferrumgate.com',
        name: 'test', source: 'local',
        password: 'passwordWithHash', groupIds: [],
        isLocked: false, isVerified: true,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()
    };
    before(async () => {
        await configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await configService.setSSLCertificate({ privateKey: fs.readFileSync('./ferrumgate.com.key').toString(), publicKey: fs.readFileSync('./ferrumgate.com.crt').toString() });


    })
    beforeEach(async () => {

        configService.config.users = [];
        configService.config.users.push(aUser);

    })
    it('verifyScope returns allways true', async () => {

        const oauthService = new OAuth2Service(configService);
        await oauthService.verifyScope({} as any, 'something');

    }).timeout(5000);

    it('revokeToken returns allways true', async () => {

        const oauthService = new OAuth2Service(configService);
        await oauthService.revokeToken({} as any);

    }).timeout(5000);

    it('generateAccessToken, getAccessToken returns an access token', async () => {

        const oauthService = new OAuth2Service(configService);
        const token = await oauthService.generateAccessToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: 'someid' }, 'ferrum');
        expect(token).to.exist;
        const tokenAccess = await oauthService.getAccessToken(token) as OAuth2Server.Token;
        expect(tokenAccess.accessTokenExpiresAt).exist;
        expect(tokenAccess.user).exist;
        expect(tokenAccess.user.id).to.equal('someid');

    }).timeout(5000);

    it('generateAccessToken, getAccessToken will throw error', async () => {

        const oauthService = new OAuth2Service(configService);
        const token = await oauthService.generateAccessToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: 'someid' }, 'ferrum');
        expect(token).to.exist;
        configService.config.users = [];//clear users
        let isError = false;
        try {
            const tokenAccess = await oauthService.getAccessToken(token) as OAuth2Server.Token;
        } catch (err) {
            isError = true;
        }
        expect(isError).to.be.true;
        //check user verification
        isError = false;
        aUser.isLocked = true;
        try {
            const tokenAccess = await oauthService.getAccessToken(token) as OAuth2Server.Token;
        } catch (err) {
            isError = true;
        }
        //reset
        aUser.isLocked = false;



    }).timeout(5000);

    it('generateAccessToken, getAccessToken will throw error because of time', async () => {
        const backup = config.JWT_TOKEN_EXPIRY_SECONDS;
        config.JWT_TOKEN_EXPIRY_SECONDS = 1;
        const oauthService = new OAuth2Service(configService);
        const token = await oauthService.generateAccessToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: 'someid' }, 'ferrum');
        expect(token).to.exist;
        await Util.sleep(2000);
        let isError = false;
        try {
            const tokenAccess = await oauthService.getAccessToken(token) as OAuth2Server.Token;
        } catch (err) {
            isError = true;
        }
        expect(isError).to.be.true;
        //set backup again
        config.JWT_TOKEN_EXPIRY_SECONDS = backup;


    }).timeout(5000);





    it('generateRefreshToken, getRefreshToken returns a refresh token', async () => {

        const oauthService = new OAuth2Service(configService);
        const token = await oauthService.generateRefreshToken({ id: 'ferrum', grants: ['refresh_token'] }, { id: 'someid' }, 'ferrum');
        expect(token).to.exist;
        const tokenRefresh = await oauthService.getRefreshToken(token) as OAuth2Server.Token;
        expect(tokenRefresh.refreshTokenExpiresAt).exist;
        expect(tokenRefresh.user).exist;
        expect(tokenRefresh.user.id).to.equal('someid');

    }).timeout(5000);

})



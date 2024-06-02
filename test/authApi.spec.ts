import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import * as twofactor from 'node-2fa';
import { ExpressApp } from '../src';
import { AuthSettings } from '../src/model/authSettings';
import { Gateway, Network } from '../src/model/network';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { UtilPKI } from '../src/utilPKI';

chai.use(chaiHttp);
const expect = chai.expect;

describe('authApi', async () => {

    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;
    const redisService = appService.redisService;
    const configService = appService.configService;
    const user: User = {
        username: 'hamza@ferrumgate.com',
        groupIds: [],
        id: 'someid',
        name: 'hamza',
        password: Util.bcryptHash('somepass'),
        source: 'local-local',
        isVerified: true,
        isLocked: false,
        is2FA: true,
        twoFASecret: twofactor.generateSecret().secret,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        roleIds: []

    }

    const user2: User = {
        username: 'hamza2@ferrumgate.com',
        groupIds: [],
        id: 'someid2',
        name: 'hamza',
        password: Util.bcryptHash('somepass'),
        source: 'local-local',
        isVerified: true,
        isLocked: false,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        roleIds: []
    }

    const net: Network = {
        id: '1ksfasdfasf',
        name: 'somenetwork',
        labels: [],
        serviceNetwork: '100.64.0.0/16',
        clientNetwork: '192.168.0.0/24',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        isEnabled: true,
    }
    const gateway: Gateway = {
        id: '123kasdfa',
        name: 'aserver',
        labels: [],
        networkId: net.id,
        isEnabled: true,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),

    }
    before(async () => {
        await expressApp.start();
    })
    after(async () => {
        await expressApp.stop();
    })

    beforeEach(async function () {
        this.timeout(120000);
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        await configService.setConfigPath(filename);
        const auth: AuthSettings = {
            common: {},
            local: {
                type: 'local',
                baseType: 'local',
                name: 'Local',
                tags: [],
                isForgotPassword: false,
                isRegister: false,
                isEnabled: true,
                insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString()
            },
            ldap: { providers: [] },
            oauth: { providers: [] },
            saml: { providers: [] },
            openId: { providers: [] },
            radius: { providers: [] }

        }
        auth.oauth = {
            providers: [
                {
                    baseType: 'oauth',
                    type: 'google',
                    id: Util.randomNumberString(),
                    name: 'Google',
                    tags: [],
                    clientId: '920409807691-jp82nth4a4ih9gv2cbnot79tfddecmdq.apps.googleusercontent.com',
                    clientSecret: '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',
                    isEnabled: true,
                    insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()
                },
                {
                    baseType: 'oauth',
                    type: 'linkedin',
                    id: Util.randomNumberString(),
                    name: 'Linkedin',
                    tags: [],
                    clientId: '866dr29tuc5uy5',
                    clientSecret: '1E3DHw0FJFUsp1Um',
                    isEnabled: true,
                    insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()
                }
            ]
        }

        auth.saml = {
            providers: [
                {
                    baseType: 'saml',
                    type: 'auth0',
                    id: Util.randomNumberString(),
                    name: 'Auth0/Saml',
                    tags: [],
                    issuer: 'urn:dev-24wm8m7g.us.auth0.com',
                    loginUrl: 'https://dev-24wm8m7g.us.auth0.com/samlp/pryXTgkqDprtoGOg0RRH26ylKV0zg4xV',
                    fingerPrint: '96:39:6C:F6:ED:DF:07:30:F0:2E:45:95:02:B6:F6:68:B7:2C:11:37',
                    cert: `MIIDDTCCAfWgAwIBAgIJDVrH9KeUS+k8MA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi0yNHdtOG03Zy51cy5hdXRoMC5jb20wHhcNMjIxMDEwMjIzOTA2WhcNMzYwNjE4MjIzOTA2WjAkMSIwIAYDVQQDExlkZXYtMjR3bThtN2cudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA14riTBaUOB2+OZiEbpL5Cjy4MVl78Qi+Msi6IbmIs8nIGRav2hYsI3/mUex6+dCeqwoKCALByRySTEWhUCRWNsi86ae5CSsRikVBAPtEZqKBuoSthrjXUQT5/UBBOHc+EVUAiNrAEE1DBjpkFPkZfGk974ZukK8MyfliajjmFHGj23vwxJncxfx49kOEalz10M500MNldl+Kl628i//y3QiojTsNvPK4SiORFBR89DnWJoB/m6npsm9tkRKUFuYNedVEDru+8aac6LVrKkimDOUzXecAbCm7+td4rXCyV25cc3Pp0sHUYFYk4NoqzW6kJtddFcRQi+xo5JqcPjtunwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRZYMCT4GSETh+A4Ji9wWJxlcv53zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBACNDPiTHjyeFUIOTWnnZbTZil0nf+yrA6QVesV5+KJ9Ek+YgMrnZ4KdXEZZozUgiGsER1RjetWVYnv3AmEvML0CY/+xJu2bCfwQssSXFLQGdv079V81Mk2+Hz8gQgruLpJpfENQCsbWm3lXQP4F3avFw68HB62rr6jfyEIPb9n8rw/pj57y5ZILl97sb3QikgRh1pTEKVz05WLeHdGPE30QWklGDYxqv2/TbRWOUsdXjjbpE6pIfTUX5OLqGRbrtdHL9fHbhVOfqczALtneEjv5o/TpB3Jo2w9RU9AgMYwWT2Hpqop/fe9fyDQ+u5Hz7ZnADi/oktGBzm8/Y03WpkuM=`,
                    usernameField: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                    nameField: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                    isEnabled: true,
                    insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()

                },
                {
                    baseType: 'saml',
                    type: 'azure',
                    id: Util.randomNumberString(),
                    name: 'Azure/Saml',
                    tags: [],
                    issuer: 'urn:dev-24wm8m7g.us.auth0.com',
                    loginUrl: 'https://dev-24wm8m7g.us.auth0.com/samlp/pryXTgkqDprtoGOg0RRH26ylKV0zg4xV',
                    fingerPrint: '96:39:6C:F6:ED:DF:07:30:F0:2E:45:95:02:B6:F6:68:B7:2C:11:37',
                    cert: `MIIDDTCCAfWgAwIBAgIJDVrH9KeUS+k8MA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi0yNHdtOG03Zy51cy5hdXRoMC5jb20wHhcNMjIxMDEwMjIzOTA2WhcNMzYwNjE4MjIzOTA2WjAkMSIwIAYDVQQDExlkZXYtMjR3bThtN2cudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA14riTBaUOB2+OZiEbpL5Cjy4MVl78Qi+Msi6IbmIs8nIGRav2hYsI3/mUex6+dCeqwoKCALByRySTEWhUCRWNsi86ae5CSsRikVBAPtEZqKBuoSthrjXUQT5/UBBOHc+EVUAiNrAEE1DBjpkFPkZfGk974ZukK8MyfliajjmFHGj23vwxJncxfx49kOEalz10M500MNldl+Kl628i//y3QiojTsNvPK4SiORFBR89DnWJoB/m6npsm9tkRKUFuYNedVEDru+8aac6LVrKkimDOUzXecAbCm7+td4rXCyV25cc3Pp0sHUYFYk4NoqzW6kJtddFcRQi+xo5JqcPjtunwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRZYMCT4GSETh+A4Ji9wWJxlcv53zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBACNDPiTHjyeFUIOTWnnZbTZil0nf+yrA6QVesV5+KJ9Ek+YgMrnZ4KdXEZZozUgiGsER1RjetWVYnv3AmEvML0CY/+xJu2bCfwQssSXFLQGdv079V81Mk2+Hz8gQgruLpJpfENQCsbWm3lXQP4F3avFw68HB62rr6jfyEIPb9n8rw/pj57y5ZILl97sb3QikgRh1pTEKVz05WLeHdGPE30QWklGDYxqv2/TbRWOUsdXjjbpE6pIfTUX5OLqGRbrtdHL9fHbhVOfqczALtneEjv5o/TpB3Jo2w9RU9AgMYwWT2Hpqop/fe9fyDQ+u5Hz7ZnADi/oktGBzm8/Y03WpkuM=`,
                    usernameField: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                    nameField: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                    isEnabled: true,
                    insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()

                },
            ]
        }
        auth.ldap = {
            providers: []
        }
        auth.openId = {
            providers: [{
                baseType: 'openId',
                type: 'generic',
                id: Util.randomNumberString(),
                name: 'OpenID/Auth0',
                tags: [],

                discoveryUrl: 'https://dev-24wm8m7g.us.auth0.com/samlp/pryXTgkqDprtoGOg0RRH26ylKV0zg4xV',
                clientId: '96:39:6C:F6:ED:DF:07:30:F0:2E:45:95:02:B6:F6:68:B7:2C:11:37',
                clientSecret: `MIIDDTCCAfWgAwIBAgIJDVrH9KeUS+k8MA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi0yNHdtOG03Zy51cy5hdXRoMC5jb20wHhcNMjIxMDEwMjIzOTA2WhcNMzYwNjE4MjIzOTA2WjAkMSIwIAYDVQQDExlkZXYtMjR3bThtN2cudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA14riTBaUOB2+OZiEbpL5Cjy4MVl78Qi+Msi6IbmIs8nIGRav2hYsI3/mUex6+dCeqwoKCALByRySTEWhUCRWNsi86ae5CSsRikVBAPtEZqKBuoSthrjXUQT5/UBBOHc+EVUAiNrAEE1DBjpkFPkZfGk974ZukK8MyfliajjmFHGj23vwxJncxfx49kOEalz10M500MNldl+Kl628i//y3QiojTsNvPK4SiORFBR89DnWJoB/m6npsm9tkRKUFuYNedVEDru+8aac6LVrKkimDOUzXecAbCm7+td4rXCyV25cc3Pp0sHUYFYk4NoqzW6kJtddFcRQi+xo5JqcPjtunwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRZYMCT4GSETh+A4Ji9wWJxlcv53zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBACNDPiTHjyeFUIOTWnnZbTZil0nf+yrA6QVesV5+KJ9Ek+YgMrnZ4KdXEZZozUgiGsER1RjetWVYnv3AmEvML0CY/+xJu2bCfwQssSXFLQGdv079V81Mk2+Hz8gQgruLpJpfENQCsbWm3lXQP4F3avFw68HB62rr6jfyEIPb9n8rw/pj57y5ZILl97sb3QikgRh1pTEKVz05WLeHdGPE30QWklGDYxqv2/TbRWOUsdXjjbpE6pIfTUX5OLqGRbrtdHL9fHbhVOfqczALtneEjv5o/TpB3Jo2w9RU9AgMYwWT2Hpqop/fe9fyDQ+u5Hz7ZnADi/oktGBzm8/Y03WpkuM=`,
                authName: "test",
                isEnabled: true,
                insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString()
            }]
        }

        await configService.saveNetwork(net);
        await configService.saveGateway(gateway);
        await configService.setAuthSettingCommon(auth.common);
        await configService.setAuthSettingLocal(auth.local);
        for (const it of auth.ldap.providers) {
            await configService.addAuthSettingLdap(it)
        }
        for (const it of auth.saml?.providers) {
            await configService.addAuthSettingSaml(it)
        }
        for (const it of auth.oauth.providers) {
            await configService.addAuthSettingOAuth(it)
        }

        await configService.setUrl('http://local.ferrumgate.com:8080')
        await configService.init();
        await configService.saveNetwork(net);
        await configService.saveGateway(gateway);
        await redisService.flushAll();
        configService.config.users = [];
        await configService.saveUser(user);
        await configService.saveUser(user2);
        configService.config.authenticationPolicy.rules = [];

    })

    it('POST /auth with 2FA result', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: 'hamza@ferrumgate.com', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.key).exist;
        expect(response.body.key.length).to.equal(48);
        expect(response.body.is2FA).to.be.true;

    }).timeout(50000);

    it('POST /auth with result 2FA false', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: 'hamza2@ferrumgate.com', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.key).exist;
        expect(response.body.key.length).to.equal(48);
        expect(response.body.is2FA).to.be.false;

    }).timeout(50000);

    it('POST /auth with result 401', async () => {

        const user5: User = {
            username: 'hamza4@ferrumgate.com',
            groupIds: [],
            id: 'someid121231',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: false,
            isLocked: false,
            is2FA: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: 'hamza4@ferrumgate.com', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response).exist;
        expect(response.status).to.equal(401);

    }).timeout(50000);

    it('POST /auth with result 200 and apikey', async () => {

        const user5: User = {
            username: 'hamza4@ferrumgate.com',
            groupIds: [],
            id: 'ipdfr6gyi3uzu8fk',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: true,
            isLocked: false,
            is2FA: true,
            apiKey: { key: 'ipdfr6gyi3uzu8fktest' },
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .set('ApiKey', 'ipdfr6gyi3uzu8fktest')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);

    }).timeout(50000);

    it('POST /auth with result 200 and certificate', async () => {

        const user5: User = {
            username: 'hamza4@ferrumgate.com',
            groupIds: [],
            id: 'ipdfr6gyi3uzu8fk',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: true,
            isLocked: false,
            is2FA: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        const ca = await configService.getCASSLCertificateSensitive();
        const inCerts = await configService.getInSSLCertificateAllSensitive();
        const cert = inCerts.find(x => x.category == 'auth');
        const userResult = await UtilPKI.createCertificate(
            {
                CN: user.id, O: 'UK', sans: [],
                isCA: false, hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5', serial: 100000,
                notAfter: new Date().addDays(5), notBefore: new Date().addDays(-10),//invalid date test
                ca: {
                    publicCrt: cert?.publicCrt || '',
                    privateKey: cert?.privateKey || '',
                    hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5'
                }
            })
        const tmpDir = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(tmpDir);
        const privateKey3 = `${tmpDir}/user.key`;
        const publicCrt3 = `${tmpDir}/user.crt`;
        fs.writeFileSync(privateKey3, UtilPKI.toPEM(userResult.privateKeyBuffer, 'PRIVATE KEY'));
        fs.writeFileSync(publicCrt3, UtilPKI.toPEM(userResult.certificateBuffer, 'CERTIFICATE'));

        user5.cert = {
            category: 'auth',
            publicCrt: fs.readFileSync(publicCrt3).toString(),
            privateKey: fs.readFileSync(privateKey3).toString()
        }

        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .set('Cert', fs.readFileSync(publicCrt3).toString('base64'))
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);

    }).timeout(50000);

    it('POST /auth with result 200 and username', async () => {

        const user5: User = {
            username: 'hx\\domain',
            groupIds: [],
            id: 'someid13131231',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local-local',
            isVerified: true,
            isLocked: false,
            is2FA: true,
            apiKey: { key: 'test' },
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: 'hx\\domain', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);

    }).timeout(50000);

    it('POST /auth with result 200 source is different but not problem', async () => {

        const user5: User = {
            username: 'hx\\domain',
            groupIds: [],
            id: 'someid121313132',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: true,
            isLocked: false,
            is2FA: false,
            apiKey: { key: 'test' },
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: 'hx\\domain', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);

    }).timeout(50000);

    it('POST /auth with result 200  because source isEnabled false and user is admin', async () => {

        const user6: User = {
            username: 'auserdomain',
            groupIds: [],
            id: 'someid222',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local-local',
            isVerified: true,
            isLocked: false,
            is2FA: false,
            apiKey: { key: 'test' },
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: ['Admin']

        }
        await configService.saveUser(user6);
        const local = await configService.getAuthSettingLocal();
        const tmp = {
            ...local
        }
        tmp.isEnabled = false;
        await configService.setAuthSettingLocal(tmp);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: 'auserdomain', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);

    }).timeout(50000);

    it('POST /auth with result 401 because source isEnabled false and user is not admin', async () => {
        //
        const user5: User = {
            username: 'hx\\domain',
            groupIds: [],
            id: 'someid11afasdfa',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local-local',
            isVerified: true,
            isLocked: false,
            is2FA: false,
            apiKey: { key: 'test' },
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: ['User']

        }
        await configService.saveUser(user5);
        const local = await configService.getAuthSettingLocal();
        const tmp = {
            ...local
        }
        tmp.isEnabled = false;
        await configService.setAuthSettingLocal(tmp);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: 'hx\\domain', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);

    }).timeout(50000);

    it('POST /auth with result 401 with empty username', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: '', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);

        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: ' ', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);

    }).timeout(50000);

    it('POST /auth with result 401', async () => {

        const user6: User = {
            username: 'hamza6@ferrumgate.com',
            groupIds: [],
            id: 'someid2323232',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: true,
            isLocked: true,
            is2FA: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user6);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: 'hamza6@ferrumgate.com', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);

    }).timeout(50000);

    it('POST /auth with result 401', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: 'hamza@ferrumgate.com', password: 'somepass222' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);

    }).timeout(50000);

    it('GET /auth/oauth/google with result 200', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/auth/oauth/google')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);

    }).timeout(50000);

    it('GET /auth/oauth/linkedin with result 200', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/auth/oauth/linkedin')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);

    }).timeout(50000);

    it('GET /auth/saml/auth0 with result 200', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/auth/saml/auth0')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.redirects.length).to.equal(1);

    }).timeout(50000);

    it('GET /auth/saml/azure with result 200', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/auth/saml/azure')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.redirects.length).to.equal(1);

    }).timeout(50000);

    it('POST /auth/2fa with result 200', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth')
                .send({ username: 'hamza@ferrumgate.com', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        const resp = response.body;
        const twoFAToken = twofactor.generateToken(user.twoFASecret || '')

        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth/2fa')
                .send({ key: resp.key, twoFAToken: twoFAToken?.token })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        const resp2 = response.body;
        expect(resp2.key).exist

    }).timeout(50000);

    it('POST /auth/accesstoken with result 200', async () => {

        await redisService.set(`/auth/access/test`, { userId: 'someid' });
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth/accesstoken')
                .send({ key: 'test' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;

    }).timeout(50000);


    it('POST /auth/accesstoken with time result 200', async () => {

        await redisService.set(`/auth/access/test`, { userId: 'someid' });
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth/accesstoken')
                .send({ key: 'test', timeInMs: 30 * 60 * 1000 })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;
        expect(response.body.accessTokenExpiresAtTime >= new Date().getTime() + 15 * 60 * 1000).to.be.true;
        expect(response.body.refreshTokenExpiresAtTime >= new Date().getTime() + 15 * 60 * 1000).to.be.true;

    }).timeout(50000);


    it('POST /auth/refreshtoken with result 200', async () => {

        await redisService.set(`/auth/access/test`, { userId: 'someid' });
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth/accesstoken')
                .send({ key: 'test' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;

        const refreshToken = response.body.refreshToken;
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth/refreshtoken')
                .set('Authorization', `Bearer ${response.body.accessToken}`)
                .send({ refreshToken: refreshToken })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;

    }).timeout(50000);


    it('POST /auth/refreshtoken with time result 200', async () => {

        await redisService.set(`/auth/access/test`, { userId: 'someid' });
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth/accesstoken')
                .send({ key: 'test', timeInMs: 30 * 60 * 1000 })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;

        const refreshToken = response.body.refreshToken;
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth/refreshtoken')
                .set('Authorization', `Bearer ${response.body.accessToken}`)
                .send({ refreshToken: refreshToken, timeInMs: 30 * 60 * 1000 })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;
        expect(response.body.accessTokenExpiresAtTime >= new Date().getTime() + 15 * 60 * 1000).to.be.true;
        expect(response.body.refreshTokenExpiresAtTime >= new Date().getTime() + 15 * 60 * 1000).to.be.true;

    }).timeout(50000);

    it('POST /auth/exchangetoken with result 200', async () => {
        await redisService.hset('/session/id/abc', { userId: 'someid', id: 'abc' })
        await redisService.set(`/exchange/id/12`, 'abc');
        const ex = Util.encrypt(configService.getEncKey(), '12')
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth/exchangetoken')
                .send({ 'exchangeKey': ex })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;

    }).timeout(50000);

    it('POST /auth/token/test with result 200', async () => {

        await redisService.set(`/auth/access/test`, { userId: 'someid' });
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth/accesstoken')
                .send({ key: 'test' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;

        const accessToken = response.body.accessToken;
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/auth/token/test')
                .set('Authorization', `Bearer ${accessToken}`)
                .send({ something: 'blada' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.works).to.be.true;

    }).timeout(50000);

})



import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { config } from 'process';
import { AuthSettings } from '../src/model/authSettings';
import * as twofactor from 'node-2fa';
import { Gateway } from '../src/model/network';
import { Network } from '../src/model/network';

chai.use(chaiHttp);
const expect = chai.expect;




describe('authApi', async () => {
    const appService = (app.appService) as AppService;
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
        clientNetwork: '192.168.0.0/24'
    }
    const gateway: Gateway = {
        id: '123kasdfa',
        name: 'aserver',
        labels: [],
        networkId: net.id,
        isEnabled: true
    }

    beforeEach(async () => {
        configService.resetUpdateTime();
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        await configService.setConfigPath(filename);
        const auth: AuthSettings = {
            common: {},
            local: {
                id: Util.randomNumberString(),
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
            ]
        }
        auth.ldap = {
            providers: []
        }



        await configService.saveNetwork(net);
        await configService.saveGateway(gateway);
        await configService.setAuthSettings(auth);
        await configService.setUrl('http://local.ferrumgate.com:8080')
        await configService.setJWTSSLCertificate({ privateKey: fs.readFileSync('./ferrumgate.com.key').toString(), publicKey: fs.readFileSync('./ferrumgate.com.crt').toString() });
        await configService.saveNetwork(net);
        await configService.saveGateway(gateway);
        await redisService.flushAll();
        configService.config.users = [];
        await configService.saveUser(user);
        await configService.saveUser(user2);

    })


    it('POST /auth with 2FA result', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth')
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
                .post('/auth')
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
                .post('/auth')
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
            id: 'someid2312313213',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: true,
            isLocked: false,
            is2FA: true,
            apiKey: 'test',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth')
                .set('ApiKey', 'test')
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
            apiKey: 'test',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth')
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

    it('POST /auth with result 401 because source is wrong', async () => {

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
            apiKey: 'test',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth')
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
            apiKey: 'test',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: ['Admin']

        }
        await configService.saveUser(user6);
        const local = await configService.getAuthSettingsLocal();
        const tmp = {
            ...local
        }
        tmp.isEnabled = false;
        await configService.setAuthSettingsLocal(tmp);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth')
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
            apiKey: 'test',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: ['User']

        }
        await configService.saveUser(user5);
        const local = await configService.getAuthSettingsLocal();
        const tmp = {
            ...local
        }
        tmp.isEnabled = false;
        await configService.setAuthSettingsLocal(tmp);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth')
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
                .post('/auth')
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
                .post('/auth')
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
                .post('/auth')
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
                .post('/auth')
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
                .get('/auth/oauth/google')
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
                .get('/auth/oauth/linkedin')
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
                .get('/auth/saml/auth0')
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
                .post('/auth')
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
                .post('/auth/2fa')
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


    it('POST /authaccesstoken with result 200', async () => {

        await redisService.set(`/auth/access/test`, 'someid');
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/accesstoken')
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


    it('POST /authaccesstoken with tunnel parameter with result 200', async () => {

        await redisService.set(`/auth/access/test`, 'someid');
        await redisService.hset(`/tunnel/testsession`, { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', hostId: gateway.id });
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/accesstoken')
                .send({ key: 'test', tunnelKey: 'testsession' })
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

        const retVAl = await redisService.hgetAll('/tunnel/testsession');
        expect(retVAl.assignedClientIp).exist;


    }).timeout(50000);


    it('POST /auth/refreshtoken with result 200', async () => {

        await redisService.set(`/auth/access/test`, 'someid');
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/accesstoken')
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
                .post('/auth/refreshtoken')
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



    it('POST /auth/token/test with result 200', async () => {

        await redisService.set(`/auth/access/test`, 'someid');
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/accesstoken')
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
                .post('/auth/token/test')
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



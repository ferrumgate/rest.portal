
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { ExpressApp } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { AuthCommon, AuthLocal, AuthSettings, BaseLdap, BaseOAuth, BaseOpenId, BaseRadius, BaseSaml } from '../src/model/authSettings';

import chaiExclude from 'chai-exclude';

chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);

function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete b.insertDate;
    delete b.updateDate;
    expect(a).to.deep.equal(b);
}


function createSampleSaml1(): BaseSaml {
    return {
        baseType: 'saml',
        type: 'auth0',
        id: Util.randomNumberString(),
        name: 'Auth0/Saml',
        tags: [],
        issuer: 'urn:dev-8m7g.us.auth0.com',
        loginUrl: 'https://dev-8m7g.us.auth0.com/samlp/pryXTgkqDp0RRH26ylKV0zg4xV',
        fingerPrint: '96:39:6C:F6:ED:DF:07:30:F0:2E:45:95:02:B6:F6:68:B7:2C:11:37',
        cert: `MIIDDTCCAfWgAwIBAgIJDVrH9KeUS+k8MA0GCSqGSIb3DQVBAMTGWRldi0yNHdtOG03Zy51cy5hdXRoMC5jb20wHhcNMjIxMDEwMjIzOTA2WhcNMzYwNjE4MjIzOTA2WjAkMSIwIAYDVQQDExlkZXYtMjR3bThtN2cudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA14riTBaUOB2+OZiEbpL5Cjy4MVl78Qi+Msi6IbmIs8nIGRav2hYsI3/mUex6+dCeqwoKCALByRySTEWhUCRWNsi86ae5CSsRikVBAPtEZqKBuoSthrjXUQT5/UBBOHc+EVUAiNrAEE1DBjpkFPkZfGk974ZukK8MyfliajjmFHGj23vwxJncxfx49kOEalz10M500MNldl+Kl628i//y3QiojTsNvPK4SiORFBR89DnWJoB/m6npsm9tkRKUFuYNedVEDru+8aac6LVrKkimDOUzXecAbCm7+td4rXCyV25cc3Pp0sHUYFYk4NoqzW6kJtddFcRQi+xo5JqcPjtunwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRZYMCT4GSETh+A4Ji9wWJxlcv53zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBACNDPiTHjyeFUIOTWnnZbTZil0nf+yrA6QVesV5+KJ9Ek+YgMrnZ4KdXEZZozUgiGsER1RjetWVYnv3AmEvML0CY/+xJu2bCfwQssSXFLQGdv079V81Mk2+Hz8gQgruLpJpfENQCsbWm3lXQP4F3avFw68HB62rr6jfyEIPb9n8rw/pj57y5ZILl97sb3QikgRh1pTEKVz05WLeHdGPE30QWklGDYxqv2/TbRWOUsdXjjbpE6pIfTUX5OLqGRbrtdHL9fHbhVOfqczALtneEjv5o/TpB3Jo2w9RU9AgMYwWT2Hpqop/fe9fyDQ+u5Hz7ZnADi/oktGBzm8/Y03WpkuM=`,
        usernameField: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        nameField: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        isEnabled: true,

        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        saveNewUser: true
    }
}


function createSampleLdap1(): BaseLdap {
    return {
        baseType: 'ldap',
        type: 'activedirectory',
        id: Util.randomNumberString(),
        name: 'ActiveDirectory',
        tags: [],
        host: 'ldap://',
        bindDN: 'cn=myadmin',
        bindPass: 'mypass',
        searchBase: 'cn=myuser',
        searchFilter: '',
        usernameField: 'aSSAm',
        groupnameField: 'memberOf',

        isEnabled: true,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        saveNewUser: true
    }
}

function createSampleOauth1(): BaseOAuth {
    return {
        baseType: 'oauth',
        type: 'google',
        id: Util.randomNumberString(),
        name: 'Google',
        tags: [],
        clientId: '920409807691-jp82nth4a4ih9gv2cbnot79tfddecmdq.apps.googleusercontent.com',
        clientSecret: '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',

        isEnabled: true,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        saveNewUser: true
    }
}
function createSampleOAuth2(): BaseOAuth {
    return {
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
}

function createSampleLocal(): AuthLocal {
    return {

        type: 'local',
        baseType: 'local',
        name: 'Local',
        tags: [],
        isForgotPassword: false,
        isRegister: false,

        isEnabled: true,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()
    }
}


function createSampleOpenId1(): BaseOpenId {
    return {
        baseType: 'openId',
        type: 'generic',
        authName: 'auth0',
        id: Util.randomNumberString(),
        name: 'OpenId/Auth0',
        tags: [],
        discoveryUrl: "https://dev-24wm8m7g.us.auth0.com/",
        clientId: "asdfas",
        clientSecret: "232sds",
        isEnabled: true,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        saveNewUser: true
    }
}

function createSampleRadius1(): BaseRadius {
    return {
        baseType: 'radius',
        type: 'generic',
        id: Util.randomNumberString(),
        name: 'FreeRadius',
        tags: [],
        host: "dev-24wm8m7g.us.auth0.com",
        secret: "232sds",
        isEnabled: true,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        saveNewUser: true
    }
}

describe('configAuthApi ', async () => {


    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;

    const redisService = appService.redisService;
    const configService = appService.configService;
    const sessionService = appService.sessionService;

    const user: User = {
        username: 'hamza@ferrumgate.com',
        groupIds: [],
        id: 'someid',
        name: 'hamza',
        source: 'local',
        roleIds: ['Admin'],
        isLocked: false, isVerified: true,
        password: Util.bcryptHash('somepass'),
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }

    before(async () => {
        await expressApp.start();
        if (fs.existsSync('/tmp/config.yaml'))
            fs.rmSync('/tmp/config.yaml')
        await configService.setConfigPath('/tmp/config.yaml');
        const auth: AuthSettings = {
            common: {},
            local: {} as any,
            saml: { providers: [] },
            ldap: { providers: [] },
            oauth: { providers: [] },
            openId: { providers: [] },
            radius: { providers: [] }


        }
        auth.oauth = {
            providers: [

            ]
        }

        await configService.setAuthSettingCommon(auth.common);
        await configService.setAuthSettingLocal(auth.local);

        await configService.setUrl('http://local.ferrumgate.com:8080');
        await configService.setDomain('ferrumgate.zero');
        await configService.setCaptcha(
            {
                client: '6Lcw_scfAAAAABL_DeZVQNd-yNHp0CnNYE55rifH',
                server: '6Lcw_scfAAAAAFKwZuGa9vxuFF7ezh8ZtsQazdS0'
            }
        )
        await configService.init();
    })
    after(async () => {
        await expressApp.stop();
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        await redisService.flushAll();
        configService.config.users = [];
        const auth: AuthSettings = {
            common: {},
            local: {} as any,
            saml: { providers: [] },
            ldap: { providers: [] },
            oauth: { providers: [] },
            openId: { providers: [] },
            radius: { providers: [] }

        }


        await configService.setAuthSettingCommon(auth.common);
        await configService.setAuthSettingLocal(auth.local);

        const tmp = await configService.getAuthSettingLdap();
        for (const it of tmp.providers) {
            await configService.deleteAuthSettingLdap(it.id);
        }
        const tmp2 = await configService.getAuthSettingOAuth();
        for (const it of tmp2.providers) {
            await configService.deleteAuthSettingOAuth(it.id);
        }
        const tmp3 = await configService.getAuthSettingSaml();
        for (const it of tmp3.providers) {
            await configService.deleteAuthSettingSaml(it.id);
        }

        const tmp4 = await configService.getAuthSettingOpenId();
        for (const it of tmp4.providers) {
            await configService.deleteAuthSettingOpenId(it.id);
        }

        const tmp5 = await configService.getAuthSettingRadius();
        for (const it of tmp5.providers) {
            await configService.deleteAuthSettingRadius(it.id);
        }


    })


    it('GET /config/auth/common will return 200, with common auth settigns', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const common: AuthCommon = {
            test: ''
        }
        await configService.setAuthSettingCommon(common);


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/config/auth/common')
                .set(`Authorization`, `Bearer ${token}`)

                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.test).exist;





    }).timeout(50000);

    it('PUT /config/auth/common will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const common: AuthCommon = {
            test: ''
        }
        //await configService.setAuthSettingCommon(common);


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/common')
                .set(`Authorization`, `Bearer ${token}`)
                .send(common)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        //check if object test property not saved
        const returned = await configService.getAuthSettingCommon() as any;
        expect(returned.test).not.exist;


    }).timeout(50000);

    it('GET /config/auth/local will return 200, with local auth settigns', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const local = createSampleLocal();
        await configService.setAuthSettingLocal(local);


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/config/auth/local')
                .set(`Authorization`, `Bearer ${token}`)

                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expectToDeepEqual(response.body, local);


    }).timeout(50000);

    it('PUT /config/auth/local will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const local = createSampleLocal();
        await configService.setAuthSettingLocal(local);
        local.name = 'changed';
        (local as any).fakeProperty = 'fakevalue';// this value will not written to config

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/local')
                .set(`Authorization`, `Bearer ${token}`)
                .send(local)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fakeProperty).not.exist;
        delete (local as any).fakeProperty;
        response.body.insertDate = local.insertDate;
        response.body.updateDate = local.updateDate;
        expectToDeepEqual(response.body, local);


    }).timeout(50000);

    ////////////////// oauth2  tests ////////////////////////////////////////////////

    it('GET /config/auth/oauth/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/config/auth/oauth/providers')
                .set(`Authorization`, `Bearer ${token}`)

                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.items).exist;
        expectToDeepEqual(response.body.items[0], oauth);


    }).timeout(50000);

    it('POST /config/auth/oauth/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);

        const oauth2 = createSampleOAuth2();
        delete (oauth2 as any).id;
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/config/auth/oauth/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(oauth2)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body).exist;

        oauth2.id = response.body.id;
        response.body.insertDate = oauth2.insertDate;
        response.body.updateDate = oauth2.updateDate;
        expectToDeepEqual(response.body, oauth2);


    }).timeout(50000);

    it('POST /config/auth/oauth/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);

        const oauth2 = createSampleOAuth2();

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/config/auth/oauth/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(oauth2)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);


    it('PUT /config/auth/oauth/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);
        const oauthAny = oauth as any;
        oauth.name = 'xxxx';
        //check this property will not be saved
        oauthAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/oauth/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(oauth)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fakeProperty).not.exist;
        delete oauthAny.fakeProperty;

        expectToDeepEqual(response.body, oauth);



    }).timeout(50000);


    it('PUT /config/auth/oauth/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);
        const oauthAny = oauth as any;
        oauth.id = 'notabsentid';
        oauth.name = 'xxxx';
        //check this property will not be saved
        oauthAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/oauth/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(oauth)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);

        delete oauthAny.id;
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/oauth/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(oauthAny)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);


    it('DELETE /config/auth/oauth/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete('/api/config/auth/oauth/providers/' + oauth.id)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        const oauthRet = await configService.getAuthSettingOAuth();
        expect(oauthRet.providers.length).to.equal(0);
    }).timeout(50000);




    ////////////////// ldap  tests ////////////////////////////////////////////////

    it('GET /config/auth/ldap/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const ldap = createSampleLdap1();
        await configService.addAuthSettingLdap(ldap);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/config/auth/ldap/providers')
                .set(`Authorization`, `Bearer ${token}`)

                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.items).exist;

        expectToDeepEqual(response.body.items[0], ldap);


    }).timeout(50000);

    it('POST /config/auth/ldap/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        const ldap = createSampleLdap1();
        delete (ldap as any).id;
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/config/auth/ldap/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(ldap)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body).exist;

        ldap.id = response.body.id;
        expectToDeepEqual(response.body, ldap);


    }).timeout(50000);

    it('POST /config/auth/ldap/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        const ldap1 = createSampleLdap1();

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/config/auth/ldap/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(ldap1)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);


    it('PUT /config/auth/ldap/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const ldap = createSampleLdap1();
        await configService.addAuthSettingLdap(ldap);
        const ldapAny = ldap as any;
        ldapAny.name = 'xxxx';
        //check this property will not be saved
        ldapAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/ldap/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(ldap)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fakeProperty).not.exist;
        delete ldapAny.fakeProperty;
        expectToDeepEqual(response.body, ldap);


    }).timeout(50000);


    it('PUT /config/auth/ldap/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const ldap = createSampleLdap1();
        await configService.addAuthSettingLdap(ldap);
        const ldapAny = ldap as any;
        ldap.id = 'notabsentid';
        ldap.name = 'xxxx';
        //check this property will not be saved
        ldapAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/ldap/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(ldap)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);

        delete ldapAny.id;
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/ldap/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(ldapAny)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);


    it('DELETE /config/auth/ldap/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const ldap = createSampleLdap1();
        await configService.addAuthSettingLdap(ldap);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete('/api/config/auth/ldap/providers/' + ldap.id)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        const ldapRet = await configService.getAuthSettingLdap();
        expect(ldapRet.providers.length).to.equal(0);
    }).timeout(50000);











    ////////////////// saml  tests ////////////////////////////////////////////////

    it('GET /config/auth/saml/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const saml = createSampleSaml1();
        await configService.addAuthSettingSaml(saml);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/config/auth/saml/providers')
                .set(`Authorization`, `Bearer ${token}`)

                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.items).exist;

        expectToDeepEqual(response.body.items[0], saml);


    }).timeout(50000);

    it('POST /config/auth/saml/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        const saml = createSampleSaml1();
        delete (saml as any).id;
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/config/auth/saml/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(saml)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body).exist;

        saml.id = response.body.id;
        response.body.insertDate = saml.insertDate;
        response.body.updateDate = saml.updateDate;

        expectToDeepEqual(response.body, saml);


    }).timeout(50000);

    it('POST /config/auth/saml/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        const saml1 = createSampleSaml1();

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/config/auth/saml/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(saml1)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);


    it('PUT /config/auth/saml/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const saml = createSampleSaml1();
        await configService.addAuthSettingSaml(saml);
        const samlAny = saml as any;
        samlAny.name = 'xxxx';
        //check this property will not be saved
        samlAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/saml/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(saml)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fakeProperty).not.exist;
        delete samlAny.fakeProperty;
        response.body.insertDate = saml.insertDate;
        response.body.updateDate = saml.updateDate;

        expectToDeepEqual(response.body, saml);


    }).timeout(50000);


    it('PUT /config/auth/saml/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const saml = createSampleSaml1();
        await configService.addAuthSettingSaml(saml);
        const samlAny = saml as any;
        saml.id = 'notabsentid';
        saml.name = 'xxxx';
        //check this property will not be saved
        samlAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/saml/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(saml)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);

        delete samlAny.id;
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/saml/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(samlAny)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);


    it('DELETE /config/auth/saml/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const saml = createSampleSaml1();
        await configService.addAuthSettingSaml(saml);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete('/api/config/auth/saml/providers/' + saml.id)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        const samlRet = await configService.getAuthSettingSaml();
        expect(samlRet.providers.length).to.equal(0);
    }).timeout(50000);



    ///////////// open id tests  /////////////////////////////////




    it('GET /config/auth/openid/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const openid = createSampleOpenId1();
        await configService.addAuthSettingOpenId(openid);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/config/auth/openid/providers')
                .set(`Authorization`, `Bearer ${token}`)

                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.items).exist;

        expectToDeepEqual(response.body.items[0], openid);


    }).timeout(50000);

    it('POST /config/auth/openid/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        const openid = createSampleOpenId1();
        delete (openid as any).id;
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/config/auth/openid/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(openid)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body).exist;

        openid.id = response.body.id;
        response.body.insertDate = openid.insertDate;
        response.body.updateDate = openid.updateDate;

        expectToDeepEqual(response.body, openid);


    }).timeout(50000);

    it('POST /config/auth/openid/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        const saml1 = createSampleOpenId1();

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/config/auth/openid/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(saml1)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);


    it('PUT /config/auth/openid/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const openid = createSampleOpenId1();
        await configService.addAuthSettingOpenId(openid);
        const openIdAny = openid as any;
        openIdAny.name = 'xxxx';
        //check this property will not be saved
        openIdAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/openid/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(openid)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fakeProperty).not.exist;
        delete openIdAny.fakeProperty;
        response.body.insertDate = openid.insertDate;
        response.body.updateDate = openid.updateDate;

        expectToDeepEqual(response.body, openid);


    }).timeout(50000);


    it('PUT /config/auth/openid/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const openid = createSampleOpenId1();
        await configService.addAuthSettingOpenId(openid);
        const openIdAny = openid as any;
        openid.id = 'notabsentid';
        openid.name = 'xxxx';
        //check this property will not be saved
        openIdAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/openid/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(openid)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);

        delete openIdAny.id;
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/openid/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(openIdAny)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);


    it('DELETE /config/auth/openid/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const openid = createSampleOpenId1();
        await configService.addAuthSettingOpenId(openid);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete('/api/config/auth/openid/providers/' + openid.id)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        const openIdRet = await configService.getAuthSettingOpenId();
        expect(openIdRet.providers.length).to.equal(0);
    }).timeout(50000);




    ///////////// radius tests  /////////////////////////////////




    it('GET /config/auth/radius/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const radius = createSampleRadius1();
        await configService.addAuthSettingRadius(radius);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/api/config/auth/radius/providers')
                .set(`Authorization`, `Bearer ${token}`)

                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.items).exist;

        expectToDeepEqual(response.body.items[0], radius);


    }).timeout(50000);

    it('POST /config/auth/radius/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        const radius = createSampleRadius1();
        delete (radius as any).id;
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/config/auth/radius/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(radius)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body).exist;

        radius.id = response.body.id;
        response.body.insertDate = radius.insertDate;
        response.body.updateDate = radius.updateDate;

        expectToDeepEqual(response.body, radius);


    }).timeout(50000);

    it('POST /config/auth/radius/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        const saml1 = createSampleRadius1();

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/config/auth/radius/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(saml1)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);


    it('PUT /config/auth/radius/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const radius = createSampleRadius1();
        await configService.addAuthSettingRadius(radius);
        const radiusAny = radius as any;
        radiusAny.name = 'xxxx';
        //check this property will not be saved
        radiusAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/radius/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(radius)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fakeProperty).not.exist;
        delete radiusAny.fakeProperty;
        response.body.insertDate = radius.insertDate;
        response.body.updateDate = radius.updateDate;

        expectToDeepEqual(response.body, radius);


    }).timeout(50000);


    it('PUT /config/auth/radius/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const radius = createSampleRadius1();
        await configService.addAuthSettingRadius(radius);
        const radiusAny = radius as any;
        radius.id = 'notabsentid';
        radius.name = 'xxxx';
        //check this property will not be saved
        radiusAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/radius/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(radius)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);

        delete radiusAny.id;
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/api/config/auth/radius/providers')
                .set(`Authorization`, `Bearer ${token}`)
                .send(radiusAny)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);


    it('DELETE /config/auth/radius/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const radius = createSampleRadius1();
        await configService.addAuthSettingRadius(radius);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete('/api/config/auth/radius/providers/' + radius.id)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        const radiusRet = await configService.getAuthSettingRadius();
        expect(radiusRet.providers.length).to.equal(0);
    }).timeout(50000);




})



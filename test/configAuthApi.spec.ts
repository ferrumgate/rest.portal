
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { config } from 'process';
import { AuthCommon, AuthLocal, AuthSettings, BaseLdap, BaseOAuth } from '../src/model/authSettings';
import { RedisService } from '../src/service/redisService';
import { EmailSettings } from '../src/model/emailSettings';


chai.use(chaiHttp);
const expect = chai.expect;


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
        securityProfile: {}
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
        securityProfile: {}
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
        securityProfile: {}
    }
}

function createSampleLocal(): AuthLocal {
    return {
        id: Util.randomNumberString(),
        type: 'local',
        baseType: 'local',
        name: 'Local',
        tags: [],
        isForgotPassword: false,
        isRegister: false,
        securityProfile: {}
    }
}

describe('configAuthApi ', async () => {
    //const simpleRedis = new RedisService('localhost:6379,localhost:6390');

    const appService = (app.appService) as AppService;
    //appService.redisService = simpleRedis;
    const redisService = appService.redisService;
    const configService = appService.configService;

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
        if (fs.existsSync('/tmp/config.yaml'))
            fs.rmSync('/tmp/config.yaml')
        await configService.setConfigPath('/tmp/config.yaml');
        const auth: AuthSettings = {
            common: {},
            local: {} as any

        }
        auth.oauth = {
            providers: [

            ]
        }

        await configService.setAuthSettings(auth);
        await configService.setUrl('http://local.ferrumgate.com:8080');
        await configService.setDomain('ferrumgate.local');
        await configService.setCaptcha(
            {
                client: '6Lcw_scfAAAAABL_DeZVQNd-yNHp0CnNYE55rifH',
                server: '6Lcw_scfAAAAAFKwZuGa9vxuFF7ezh8ZtsQazdS0'
            }
        )
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        await redisService.flushAll();
        configService.config.users = [];
        const auth: AuthSettings = {
            common: {},
            local: {} as any

        }
        auth.oauth = {
            providers: [

            ]
        },
            auth.ldap = {
                providers: []
            },
            auth.saml = {
                providers: []
            }

        await configService.setAuthSettings(auth);


    })


    it('GET /config/auth/common will return 200, with common auth settigns', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const common: AuthCommon = {
            test: ''
        }
        await configService.setAuthSettingsCommon(common);


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/auth/common')
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
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const common: AuthCommon = {
            test: ''
        }
        //await configService.setAuthSettingsCommon(common);


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/auth/common')
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
        const returned = await configService.getAuthSettingsCommon() as any;
        expect(returned.test).not.exist;


    }).timeout(50000);

    it('GET /config/auth/local will return 200, with local auth settigns', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const local = createSampleLocal();
        await configService.setAuthSettingsLocal(local);


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/auth/local')
                .set(`Authorization`, `Bearer ${token}`)

                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body).to.deep.equal(local)


    }).timeout(50000);

    it('PUT /config/auth/local will return 200', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const local = createSampleLocal();
        await configService.setAuthSettingsLocal(local);
        local.name = 'changed';
        (local as any).fakeProperty = 'fakevalue';// this value will not written to config

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/auth/local')
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
        expect(response.body).to.deep.equal(local);


    }).timeout(50000);

    ////////////////// oauth2  tests ////////////////////////////////////////////////

    it('GET /config/auth/oauth/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/auth/oauth/providers')
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

        expect(response.body.items[0]).to.deep.equal(oauth);


    }).timeout(50000);

    it('POST /config/auth/oauth/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);

        const oauth2 = createSampleOAuth2();
        delete (oauth2 as any).id;
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/config/auth/oauth/providers')
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
        expect(response.body).to.deep.equal(oauth2);


    }).timeout(50000);

    it('POST /config/auth/oauth/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);

        const oauth2 = createSampleOAuth2();

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/config/auth/oauth/providers')
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
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);
        const oauthAny = oauth as any;
        oauth.name = 'xxxx';
        //check this property will not be saved
        oauthAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/auth/oauth/providers')
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
        expect(response.body).to.deep.equal(oauth);


    }).timeout(50000);


    it('PUT /config/auth/oauth/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);
        const oauthAny = oauth as any;
        oauth.id = 'notabsentid';
        oauth.name = 'xxxx';
        //check this property will not be saved
        oauthAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/auth/oauth/providers')
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
                .put('/config/auth/oauth/providers')
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
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const oauth = createSampleOauth1();
        await configService.addAuthSettingOAuth(oauth);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete('/config/auth/oauth/providers/' + oauth.id)
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
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const ldap = createSampleLdap1();
        await configService.addAuthSettingLdap(ldap);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/auth/ldap/providers')
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

        expect(response.body.items[0]).to.deep.equal(ldap);


    }).timeout(50000);

    it('POST /config/auth/ldap/providers will return 200', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')


        const ldap = createSampleLdap1();
        delete (ldap as any).id;
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/config/auth/ldap/providers')
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
        expect(response.body).to.deep.equal(ldap);


    }).timeout(50000);

    it('POST /config/auth/ldap/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')


        const ldap1 = createSampleLdap1();

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/config/auth/ldap/providers')
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
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const ldap = createSampleLdap1();
        await configService.addAuthSettingLdap(ldap);
        const ldapAny = ldap as any;
        ldapAny.name = 'xxxx';
        //check this property will not be saved
        ldapAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/auth/ldap/providers')
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
        expect(response.body).to.deep.equal(ldap);


    }).timeout(50000);


    it('PUT /config/auth/ldap/providers will return 400', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const ldap = createSampleLdap1();
        await configService.addAuthSettingLdap(ldap);
        const ldapAny = ldap as any;
        ldap.id = 'notabsentid';
        ldap.name = 'xxxx';
        //check this property will not be saved
        ldapAny.fakeProperty = 'fakevalue';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/auth/ldap/providers')
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
                .put('/config/auth/oauth/providers')
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
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const ldap = createSampleLdap1();
        await configService.addAuthSettingLdap(ldap);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete('/config/auth/ldap/providers/' + ldap.id)
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










})




import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { config } from 'process';
import { AuthCommon, AuthSettings } from '../src/model/authSettings';
import { RedisService } from '../src/service/redisService';
import { EmailSettings } from '../src/model/emailSettings';


chai.use(chaiHttp);
const expect = chai.expect;




describe('configApi ', async () => {
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


    })
    it('GET /config/public will return public configs', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/public')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.captchaSiteKey).exist;
        expect(response.body.captchaSiteKey).to.equal('6Lcw_scfAAAAABL_DeZVQNd-yNHp0CnNYE55rifH');


    }).timeout(50000);

    it('GET /config/common will return url and domain', async () => {
        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/common')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.url).exist;
        expect(response.body.domain).to.equal('ferrumgate.local');


    }).timeout(50000);

    it('GET /config/common will return 401, only admin users', async () => {
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/common')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);



    }).timeout(50000);


    it('PUT /config/common will return 200, with new fields', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const newValues = {
            domain: 'ferrumgate.com'
        }

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/common')
                .set(`Authorization`, `Bearer ${token}`)
                .send(newValues)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.domain).to.equal('ferrumgate.com');
        expect(response.body.url).to.equal('http://local.ferrumgate.com:8080');



    }).timeout(50000);




    it('GET /config/captcha will return keys', async () => {
        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/captcha')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.server).exist;
        expect(response.body.client).exist;


    }).timeout(50000);

    it('GET /config/captcha will return 401, only admin users', async () => {
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/captcha')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);



    }).timeout(50000);


    it('PUT /config/captcha will return 200, with new fields', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const newValues = {
            server: 'serverkey',
            client: 'clientkey'
        }

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/captcha')
                .set(`Authorization`, `Bearer ${token}`)
                .send(newValues)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.server).to.equal('serverkey');
        expect(response.body.client).to.equal('clientkey');



    }).timeout(50000);

    /// email


    it('GET /config/email will return settings', async () => {
        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const emailSettings: EmailSettings = {
            fromname: 'testferrum', pass: 'apass', type: 'google', user: 'auser'
        }
        await appService.configService.setEmailSettings(emailSettings);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/email')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fromname).to.equal(emailSettings.fromname);
        expect(response.body.pass).exist;


    }).timeout(50000);

    it('GET /config/email will return 401, only admin users', async () => {
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/email')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);



    }).timeout(50000);


    it('PUT /config/email will return 200, with new fields', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const emailSettings: EmailSettings = {
            fromname: 'testferrum', pass: 'apass', type: 'google', user: 'auser'
        }
        await appService.configService.setEmailSettings(emailSettings);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/captcha')
                .set(`Authorization`, `Bearer ${token}`)
                .send({ ...emailSettings, fromname: 'ferrumgate' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fromname).to.equal('ferrumgate');




    }).timeout(50000);


    it('DELETE /config/email will return 200, with new fields', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const emailSettings: EmailSettings = {
            fromname: 'testferrum', pass: 'apass', type: 'google', user: 'auser'
        }
        await appService.configService.setEmailSettings(emailSettings);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete('/config/email')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fromname).to.equal('');
        expect(response.body.type).to.equal('empty');




    }).timeout(50000);

    it.skip('POST /config/email/check will return 200, with no error', async () => {

        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')
        const emailSettings: EmailSettings = {
            fromname: 'testferrum', pass: 'nqquxankumksakon', type: 'google', user: 'ferrumgates@gmail.com'
        }


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/config/email/check')
                .set(`Authorization`, `Bearer ${token}`)
                .send({ settings: emailSettings, to: 'hamza@hamzakilic.com' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.isError).to.equal(false);
        expect(response.body.errorMessage).to.equal('');




    }).timeout(50000);



})



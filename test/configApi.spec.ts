
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { config } from 'process';
import { AuthSettings } from '../src/model/authSettings';
import { RedisService } from '../src/service/redisService';


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
            local: {

            },
            google: {
                clientID: '920409807691-jp82nth4a4ih9gv2cbnot79tfddecmdq.apps.googleusercontent.com',
                clientSecret: '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',
            },
            linkedin: {
                clientID: '866dr29tuc5uy5',
                clientSecret: '1E3DHw0FJFUsp1Um',
            }
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











})



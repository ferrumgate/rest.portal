
import chai from 'chai';
import chaiHttp from 'chai-http';
import { AppService } from '../src/service/appService';
import { ExpressApp } from '../src/index';
import { User } from '../src/model/user';
import { Email, EmailService } from '../src/service/emailService';
import fs from 'fs';
import { Util } from '../src/util';
import { config } from 'process';

chai.use(chaiHttp);
const expect = chai.expect;




describe('userApiInvite', async () => {
    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;

    const redisService = appService.redisService;
    const emailService = appService.emailService;
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
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.init();
    })

    after(async () => {
        await expressApp.stop();
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        await redisService.flushAll();
    })
    afterEach(async () => {
        appService.emailService = emailService;
        await configService.setEmailSetting({ type: 'empty', fromname: '', pass: '', user: '' })
    })


    it('POST /user/invite will return 401', async () => {
        //prepare data
        const cloned = Util.clone(user);
        cloned.roleIds = [];
        await appService.configService.saveUser(cloned);
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        const session = await sessionService.createSession({ id: user.id } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: user.id, grants: [] }, { id: user.id, sid: session.id }, 'ferrum')



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/user/invite')
                .set(`Authorization`, `Bearer ${token}`)
                .send({ emails: ['test@ferrumgate.com'] })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(401);


    }).timeout(50000);


    it('POST /user/invite will return 400', async () => {
        //prepare data
        await appService.configService.saveUser(user);

        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        configService.setEmailSetting({ type: 'empty', fromname: '', pass: '', user: '' })
        appService.emailService = new MockEmail(configService);
        const session = await sessionService.createSession({ id: user.id } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: user.id, grants: [] }, { id: user.id, sid: session.id }, 'ferrum')



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/user/invite')
                .set(`Authorization`, `Bearer ${token}`)
                .send({ emails: ['test@ferrumgate.com'] })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);


    }).timeout(50000);

    it('POST /user/invite will return 200 with everything ok', async () => {
        //prepare data
        await appService.configService.saveUser(user);

        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        configService.setEmailSetting({ fromname: 'test', pass: 'asdfa', type: 'google', user: 'asdfa' })
        appService.emailService = new MockEmail(configService);
        const session = await sessionService.createSession({ id: user.id } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: user.id, grants: [] }, { id: user.id, sid: session.id }, 'ferrum')



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/user/invite')
                .set(`Authorization`, `Bearer ${token}`)
                .send({ emails: ['test@ferrumgate.com'] })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.results.length).to.equal(1);


    }).timeout(50000);


    it('POST /user/invite will return 200 with one of them failed ok', async () => {
        //prepare data
        await appService.configService.saveUser(user);

        class MockEmail extends EmailService {
            counter = 0;
            override  async send(email: Email): Promise<void> {
                this.counter++;
                if (this.counter == 2) throw new Error('fake error');
            }
        }
        configService.setEmailSetting({ fromname: 'test', pass: 'asdfa', type: 'google', user: 'asdfa' })
        appService.emailService = new MockEmail(configService);
        const session = await sessionService.createSession({ id: user.id } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: user.id, grants: [] }, { id: user.id, sid: session.id }, 'ferrum')



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/api/user/invite')
                .set(`Authorization`, `Bearer ${token}`)
                .send({ emails: ['test@ferrumgate.com', 'test2@ferrumgate.com'] })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        expect(response.body.results.length).to.equal(2);
        expect(response.body.results.filter((x: any) => x.errMsg).length).to.equal(1);


    }).timeout(50000);

    /*  it('POST /user/confirm will return 401 not found key', async () => {
         //prepare data
         await appService.configService.saveUser(user);
         await redisService.set('/user/confirm/deneme2', 'someid');
 
         let response: any = await new Promise((resolve: any, reject: any) => {
             chai.request(app)
                 .post('/api/user/confirmemail?key=deneme')
                 .end((err, res) => {
                     if (err)
                         reject(err);
                     else
                         resolve(res);
                 });
         })
         expect(response.status).to.equal(401);
         //redis key must be absent
         let value = await redisService.get(`/user/confirm/deneme2`, false);
         expect(value).to.exist;
     }).timeout(50000);
 
 
     it('POST /user/confirm will return 401 not found user', async () => {
         //prepare data
         await appService.configService.saveUser(user);
         await redisService.set('/user/confirm/deneme', 'someid2');
 
         let response: any = await new Promise((resolve: any, reject: any) => {
             chai.request(app)
                 .post('/api/user/confirmemail?key=deneme')
                 .end((err, res) => {
                     if (err)
                         reject(err);
                     else
                         resolve(res);
                 });
         })
         expect(response.status).to.equal(401);
         //redis key must be absent
         let value = await redisService.get(`/user/confirm/deneme`, false);
         expect(value).to.exist;
     }).timeout(50000); */


})



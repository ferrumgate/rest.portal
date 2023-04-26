
import chai from 'chai';
import chaiHttp from 'chai-http';
import { AppService } from '../src/service/appService';
import { User } from '../src/model/user';
import { Email, EmailService } from '../src/service/emailService';
import { ExpressApp } from '../src';


chai.use(chaiHttp);
const expect = chai.expect;




describe('userApiConfirm', async () => {
    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;

    const redisService = appService.redisService;
    const emailService = appService.emailService;
    const configService = appService.configService;
    const user: User = {
        username: 'hamza@ferrumgate.com',
        groupIds: [],
        id: 'someid',
        name: 'hamza',
        source: 'local',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }
    before(async () => {
        await expressApp.start();
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.setIsConfigured(1);
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
    })


    it('POST /user/confirmemail will return 200', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);
        await redisService.set('/user/confirm/deneme', 'someid');

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
        expect(response.status).to.equal(200);
        //redis key must be absent
        let value = await redisService.get(`/user/confirm/deneme`, false);
        expect(value).to.be.null;
    }).timeout(50000);

    it('POST /user/confirm will return 401 not found key', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
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
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
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
    }).timeout(50000);


})



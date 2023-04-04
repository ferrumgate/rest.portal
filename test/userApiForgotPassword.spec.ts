
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { User } from '../src/model/user';
import { Email, EmailService } from '../src/service/emailService';
import { ExpressApp } from '../src';


chai.use(chaiHttp);
const expect = chai.expect;




describe('userApiForgotPassword', async () => {
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
        await appService.configService.setEmailSetting({ fromname: 'ferrumgate', type: 'google', user: 'ferrumgates@gmail.com', pass: '}Q]@c836}7$F+AwK' })

        await appService.configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await appService.configService.saveConfigToFile();
        await appService.configService.loadConfigFromFile();
    })
    after(async () => {
        await expressApp.stop();
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        await appService.configService.setIsConfigured(1);
        await appService.configService.setAuthSettingLocal({ isForgotPassword: true } as any)
        await redisService.flushAll();
    })

    afterEach(async () => {
        appService.emailService = emailService;
    })

    it('POST /user/forgotpass will return 400 with undefined email parameter', async () => {

        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/forgotpass')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);

    }).timeout(50000);

    it('POST /user/forgotpass will return 200 with not found user parameter', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/forgotpass')
                .send({ username: 'deneme@ferrumgate.com' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

    }).timeout(50000);



    it('POST /user/forgotpass will return 200 with found user', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/forgotpass')
                .send({ username: user.username })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

    }).timeout(50000);


    it('POST /user/forgotpass will return 415 because of not configured system', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);
        await appService.configService.setIsConfigured(0);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/forgotpass')
                .send({ username: user.username })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(417);

    }).timeout(50000);
    it('POST /user/forgotpass will return 405 because of not enabled forgot password', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);
        await appService.configService.setIsConfigured(1);
        await appService.configService.setAuthSettingLocal({ isForgotPassword: false } as any);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/forgotpass')
                .send({ username: user.username })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(405);

    }).timeout(50000);




})



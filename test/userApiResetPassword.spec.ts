
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { ExpressApp } from '../src/index';
import { User } from '../src/model/user';
import { Email, EmailService } from '../src/service/emailService';


chai.use(chaiHttp);
const expect = chai.expect;




describe('userApiResetPassword', async () => {
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
        updateDate: new Date().toISOString(),


    }
    before(async () => {
        await expressApp.start();
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.setEmailSetting({ fromname: 'ferrumgate', type: 'google', user: 'ferrumgates@gmail.com', pass: '}Q]@c836}7$F+AwK' })

        await appService.configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await appService.configService.saveConfigToFile();
        await appService.configService.loadConfigFromFile();
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

    it('POST /user/resetpass will return 400 with undefined pass parameter', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/resetpass')
                .send({ key: 'deneme' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);

    }).timeout(50000);

    it('POST /user/resetpass will return 401 with not found key parameter', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/resetpass')
                .send({ pass: 'somepassDea1321', key: 'denememe' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(401);

    }).timeout(50000);

    it('POST /user/resetpass will return 400 with password policy', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/resetpass')
                .send({ pass: 'somepass', key: 'denememe' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);

    }).timeout(50000);



    it('POST /user/resetpass will return 401 with not found user', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);
        await appService.redisService.set(`/user/resetpass/deneme`, 'someid2');
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/resetpass')
                .send({ pass: 'somePas232323', key: 'deneme' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(401);

    }).timeout(50000);

    it('POST /user/resetpass will return 200 with found user', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //prepare data
        await appService.configService.saveUser(user);
        await appService.redisService.set(`/user/resetpass/deneme`, 'someid');
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/resetpass')
                .send({ pass: 'deneSad223111', key: 'deneme' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const value = await appService.redisService.get(`/user/resetpass/deneme`);
        expect(value).to.be.null;

    }).timeout(50000);





})



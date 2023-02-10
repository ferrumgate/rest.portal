
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { AuthLocal } from '../src/model/authSettings';
import { Email, EmailService } from '../src/service/emailService';
import { Redis } from 'ioredis';


chai.use(chaiHttp);
const expect = chai.expect;




describe('registerApi', async () => {
    const appService = app.appService as AppService;
    const emailService = appService.emailService;
    const configService = appService.configService;
    const redisService = appService.redisService;
    before(async () => {
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.setEmailSetting({ fromname: 'ferrumgate', type: 'google', user: 'ferrumgates@gmail.com', pass: '}Q]@c836}7$F+AwK' })

        await appService.configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await appService.configService.saveConfigToFile();
        await appService.configService.loadConfigFromFile();
    })

    beforeEach(async () => {
        await redisService.flushAll();
        appService.configService.config.users = [];
        await appService.configService.setIsConfigured(1);
        await appService.configService.setAuthSettingLocal({ isRegister: 1 } as any)

    })

    afterEach(async () => {
        appService.emailService = emailService;
    })



    it('POST /register will return 400 bad argument', async () => {
        //we must send right paramters
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);
    }).timeout(5000);

    it('POST /register will return 200', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //we must send right paramters
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register')
                .send({ name: "test", username: "hamza@hamzakilic.com", password: "passDeneme122" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
    }).timeout(50000);

    it('POST /register will return 417 because of not configured system', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //we must send right paramters
        await appService.configService.setIsConfigured(0);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register')
                .send({ name: "test", username: "hamza@hamzakilic", password: "passDene12321" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(417);
    }).timeout(5000);

    it('POST /register will return 405 because of register not enabled', async () => {
        //we must send right paramters
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);

        await appService.configService.setAuthSettingLocal({ isRegister: 0 } as any)
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register')
                .send({ name: "test", username: "hamza@hamzakilic", password: "passDene12321" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(405);
    }).timeout(5000);

    it('POST /register will return 400 because of invalid email', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //we must send right paramters
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register')
                .send({ name: "test", username: "hamza@hamzakilic", password: "passDene12321" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);
    }).timeout(5000);


    it('POST /register will return 400 because of invalid password', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //we must send right paramters
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register')
                .send({ name: "test", username: "hamza@hamzakilic.com", password: "pass12321" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);
    }).timeout(5000);


    it('POST /register will return 200 because allready user exits, will send a reset password email', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //we must send right paramters

        appService.configService.config.users.push({ username: 'hamza@hamzakilic.com' } as User);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register')
                .send({ name: "test", username: "hamza@hamzakilic.com", password: "passDe121ad!!" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
    }).timeout(5000);



    it('POST /register/invite will return 400 because of sended parameters', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //we must send right paramters


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register/invite')
                .send({ name: "test", password: "passDe121ad!!" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);
    }).timeout(5000);

    it('POST /register/invite will return 417 because system not configured', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //we must send right paramters

        await appService.configService.setIsConfigured(0);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register/invite')
                .send({ name: "test", key: 'adsdf', password: "passDe121ad!!" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(417);
    }).timeout(5000);

    it('POST /register/invite will return 401 key not found', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //we must send right paramters


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register/invite')
                .send({ name: "test", key: 'adsdf', password: "passDe121ad!!" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(401);
    }).timeout(5000);


    it('POST /register/invite will return 400 password policy', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //we must send right paramters
        await redisService.set(`/register/invite/adsdf`, { email: 'test@ferrumgate.com' });

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register/invite')
                .send({ name: "test", key: 'adsdf', password: "passDe" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);
    }).timeout(5000);


    it('POST /register/invite will return 200', async () => {
        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        //we must send right paramters
        await redisService.set(`/register/invite/adsdf`, { email: 'test@ferrumgate.com' });

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/register/invite')
                .send({ name: "test", key: 'adsdf', password: "passD7e@@ad!!dA" })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const user = await configService.getUserByUsername('test@ferrumgate.com')
        expect(user).exist;
    }).timeout(5000);



})



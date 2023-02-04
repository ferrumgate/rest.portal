
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { AuthLocal } from '../src/model/authSettings';


chai.use(chaiHttp);
const expect = chai.expect;




describe('registerApi', async () => {
    const appService = app.appService as AppService;

    before(async () => {
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.setEmailSetting({ fromname: 'ferrumgate', type: 'google', user: 'ferrumgates@gmail.com', pass: '}Q]@c836}7$F+AwK' })

        await appService.configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await appService.configService.saveConfigToFile();
        await appService.configService.loadConfigFromFile();
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        await appService.configService.setIsConfigured(1);
        await appService.configService.setAuthSettingLocal({ isRegister: 1 } as any)

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

    it.skip('POST /register will return 200', async () => {
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


    it.skip('POST /register will return 200 because allready user exits, will send a reset password email', async () => {
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

})



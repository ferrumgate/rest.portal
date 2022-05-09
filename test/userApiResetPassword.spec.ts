
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';


chai.use(chaiHttp);
const expect = chai.expect;




describe.skip('userApiResetPassword', async () => {
    const appService = app.appService as AppService;
    const redisService = appService.redisService;
    const user: User = {
        email: 'hamza@ferrumgate.com',
        groupIds: [],
        id: 'someid',
        name: 'hamza',
        source: 'local',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }
    before(async () => {
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.setEmailOptions({ fromname: 'ferrumgate', type: 'google', user: 'ferrumgates@gmail.com', pass: '}Q]@c836}7$F+AwK' })

        await appService.configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await appService.configService.saveConfigToFile();
        await appService.configService.loadConfigFromFile();
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        await redisService.flushAll();
    })

    it('POST /user/resetpass will return 400 with undefined pass parameter', async () => {
        //prepare data
        await appService.configService.saveUser(user);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/resetpass/deneme')
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
        //prepare data
        await appService.configService.saveUser(user);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/resetpass/denememe')
                .send({ pass: 'somepassDea1321' })
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
        //prepare data
        await appService.configService.saveUser(user);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/resetpass/denememe')
                .send({ pass: 'somepass' })
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
        //prepare data
        await appService.configService.saveUser(user);
        await appService.redisService.set(`user_resetpass_deneme`, 'someid2');
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/resetpass/deneme')
                .send({ pass: 'somePas232323' })
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
        //prepare data
        await appService.configService.saveUser(user);
        await appService.redisService.set(`user_resetpass_deneme`, 'someid');
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/user/resetpass/deneme')
                .send({ pass: 'deneSad223111' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const value = await appService.redisService.get(`user_resetpass_deneme`);
        expect(value).to.be.null;

    }).timeout(50000);





})



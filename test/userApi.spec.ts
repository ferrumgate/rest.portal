
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';


chai.use(chaiHttp);
const expect = chai.expect;




describe('userApi', async () => {
    const appService = app.appService as AppService;
    const redisService = appService.redisService;
    const user: User = {
        email: 'hamza@ferrumgate.com',
        groupIds: [],
        id: 'someid',
        name: 'hamza',
        source: 'local'

    }
    before(async () => {
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        await redisService.flushAll();
    })


    it('GET /user/confirm/:key will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        await redisService.set('account_confirm_deneme', 'someid');

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/user/confirm/deneme')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        //redis key must be absent
        let value = await redisService.get(`account_confirm_deneme`, false);
        expect(value).to.be.null;
    }).timeout(50000);

    it('GET /user/confirm/:key will return 401 not found key', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        await redisService.set('account_confirm_deneme2', 'someid');

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/user/confirm/deneme')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(401);
        //redis key must be absent
        let value = await redisService.get(`account_confirm_deneme2`, false);
        expect(value).to.exist;
    }).timeout(50000);


    it('GET /user/confirm/:key will return 401 not found user', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        await redisService.set('account_confirm_deneme', 'someid2');

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/user/confirm/deneme')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(401);
        //redis key must be absent
        let value = await redisService.get(`account_confirm_deneme`, false);
        expect(value).to.exist;
    }).timeout(50000);



})



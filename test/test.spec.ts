
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';


chai.use(chaiHttp);
const expect = chai.expect;




describe('/api/test ', async () => {


    beforeEach(async () => {
        await (app.appService as AppService).redisService.flushAll();
    })
    it('GET /test', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/test')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);

                });
        })

        expect(response.status).to.equal(200);

    }).timeout(5000);


    it('check clientip', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/test')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);

                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.clientIp).exist;

    }).timeout(5000);


    it('check ratelimit ', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/test')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);

                });
        })

        expect(response.status).to.equal(200);
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/test')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);

                });
        })

        expect(response.status).to.equal(200);
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/test')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);

                });
        })

        expect(response.status).to.equal(429);

    }).timeout(50000);

})



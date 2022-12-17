
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Gateway } from '../src/model/network';

import chaiExclude from 'chai-exclude';

chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);


/**
 * authenticated user api tests
 */
describe('gatewayApi', async () => {
    const appService = app.appService as AppService;
    const redisService = appService.redisService;
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
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.setJWTSSLCertificate({ privateKey: fs.readFileSync('./ferrumgate.com.key').toString(), publicKey: fs.readFileSync('./ferrumgate.com.crt').toString() });
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        appService.configService.config.networks = [];
        appService.configService.config.gateways = [];
        await redisService.flushAll();
    })


    it('check authoration as admin role', async () => {
        //prepare data
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const gateway: Gateway = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveGateway(gateway);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/gateway/${gateway.id}`)
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


    it('GET /gateway/:id returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const gateway: Gateway = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            networkId: '2aksa',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveGateway(gateway);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/gateway/${gateway.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).to.excluding(['insertDate', 'updateDate']).deep.equal(gateway);

    }).timeout(50000);

    it('GET /gateway/:id returns 401', async () => {
        //prepare data

        await appService.configService.saveUser(user);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/gateway/id`)
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


    it('GET /gateway?search=bla returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const gateway: Gateway = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            networkId: '2aksa',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveGateway(gateway);

        const gateway2: Gateway = {
            id: Util.randomNumberString(),
            name: 'test2',
            labels: ['mest'],
            networkId: '2aksa',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveGateway(gateway2);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/gateway?search=mest`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.items[0]).to.excluding(['insertDate', 'updateDate']).deep.equal(gateway2);

    }).timeout(50000);

    it('DELETE /gateway/:id returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const gateway: Gateway = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            networkId: '2aksa',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveGateway(gateway);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/gateway/${gateway.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const itemDb = await appService.configService.getGateway(gateway.id);
        expect(itemDb).not.exist;

    }).timeout(50000);


    it('PUT /gateway returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const gateway: Gateway = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            networkId: '2aksa',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveGateway(gateway);
        gateway.name = 'blabla'
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/gateway`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(gateway)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const itemDb = await appService.configService.getGateway(gateway.id);
        expect(itemDb).to.excluding(['insertDate', 'updateDate']).deep.equal(gateway);

    }).timeout(50000);



    it('POST /gateway returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const gateway: Gateway = {
            id: '',
            name: 'test',
            labels: [],
            networkId: '2aksa',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/gateway`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(gateway)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        gateway.id = response.body.id;
        expect(response.body).to.excluding(['insertDate', 'updateDate']).deep.equal(gateway);

    }).timeout(50000);




})




import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Service } from '../src/model/service';
import { Network } from '../src/model/network';
import { getEmptyServiceIp } from '../src/api/serviceApi';

import chaiExclude from 'chai-exclude';

chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);

function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete b.insertDate;
    delete b.updateDate;
    expect(a).to.deep.equal(b);
}

function createSampleData() {
    let network: Network = {
        id: 'network1',
        clientNetwork: '10.0.0.1/24',
        serviceNetwork: '10.0.0.0/24',
        labels: [],
        name: 'network',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }
    let service1: Service = {
        id: Util.randomNumberString(),
        name: 'mysql-dev',
        isEnabled: true,
        labels: [],
        host: '1.2.3.4',
        networkId: 'network1',
        tcp: 3306,
        protocol: 'raw',
        assignedIp: '10.0.0.1',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        count: 1


    }
    let service2: Service = {
        id: Util.randomNumberString(),
        name: 'remote-desktop-dev',
        isEnabled: true,
        labels: ['test'],
        host: '192.168.10.10',
        networkId: 'network1',
        tcp: 3306,
        protocol: 'raw',
        assignedIp: '10.0.0.1',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        count: 1

    }
    const user1: User = {
        username: 'hamza@ferrumgate.com',
        id: 'someid',
        name: 'hamza',
        source: 'local',
        roleIds: ['Admin'],
        isLocked: false, isVerified: true,
        password: Util.bcryptHash('somepass'),
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        groupIds: []

    }

    return { service1, service2, user1, network };
}
/**
 * authenticated service api
 */
describe('serviceApi', async () => {
    const appService = app.appService as AppService;
    const redisService = appService.redisService;
    const sessionService = appService.sessionService;
    before(async () => {
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.setJWTSSLCertificate({ privateKey: fs.readFileSync('./ferrumgate.com.key').toString(), publicKey: fs.readFileSync('./ferrumgate.com.crt').toString() });
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        appService.configService.config.groups = [];
        appService.configService.config.services = [];
        appService.configService.config.networks = [];
        appService.configService.config.gateways = [];
        await redisService.flushAll();
    })


    it('check authorazion as admin role', async () => {
        //prepare data
        const { service1, service2, user1, network } = createSampleData();
        await appService.configService.saveNetwork(network);
        const clonedUser = Util.clone(user1);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/service/${service1.id}`)
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


    it('GET /service/:id returns 200', async () => {
        //prepare data
        const { service1, service2, user1, network } = createSampleData();
        await appService.configService.saveNetwork(network);
        await appService.configService.saveUser(user1);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveService(service1);
        await appService.configService.saveService(service2);


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/service/${service2.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        expectToDeepEqual(response.body, service2);

    }).timeout(50000);

    it('GET /service/:id returns 401', async () => {
        //prepare data
        const { service1, service2, user1, network } = createSampleData();
        await appService.configService.saveNetwork(network);
        await appService.configService.saveUser(user1);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        await appService.configService.saveService(service1);
        await appService.configService.saveService(service2);


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/service/absentGroupId`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        //specific return, why one gets an unknown 
        expect(response.status).to.equal(401);


    }).timeout(50000);


    it('GET /service?search=bla returns 200', async () => {
        //prepare data
        const { service1, service2, user1, network } = createSampleData();
        await appService.configService.saveNetwork(network);
        await appService.configService.saveUser(user1);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        service1.labels = ['bla'];
        await appService.configService.saveService(service1);
        await appService.configService.saveService(service2);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/service?search=bla`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expectToDeepEqual(response.body.items[0], service1);

    }).timeout(50000);

    it('DELETE /service/:id returns 200', async () => {
        //prepare data
        const { service1, service2, user1, network } = createSampleData();
        await appService.configService.saveNetwork(network);
        await appService.configService.saveUser(user1);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        await appService.configService.saveService(service1);
        await appService.configService.saveService(service2);


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/service/${service2.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const itemDb = await appService.configService.getService(service2.id);
        expect(itemDb).not.exist;

    }).timeout(50000);


    it('PUT /service returns 200', async () => {
        //prepare data
        const { service1, service2, user1, network } = createSampleData();
        await appService.configService.saveNetwork(network);
        await appService.configService.saveUser(user1);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        await appService.configService.saveService(service1);
        await appService.configService.saveService(service2);

        service2.name = 'blabla'
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/service`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(service2)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const itemDb = await appService.configService.getService(service2.id);
        if (itemDb) {
            itemDb.insertDate = service2.insertDate;
            itemDb.updateDate = service2.updateDate;
        }
        expectToDeepEqual(itemDb, service2);

    }).timeout(50000);



    it('POST /service returns 200', async () => {
        //prepare data
        const { service1, service2, user1, network } = createSampleData();
        await appService.configService.saveNetwork(network);
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        await appService.configService.saveService(service1);

        service2.id = '';

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/service`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(service2)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        service2.id = response.body.id;
        service2.assignedIp = response.body.assignedIp;
        service2.insertDate = response.body.insertDate;
        service2.updateDate = response.body.updateDate;

        expectToDeepEqual(response.body, service2);

    }).timeout(50000);


    it('getEmptyServiceIp', async () => {

        let network = {
            serviceNetwork: '10.0.0.0/24'
        } as Network;

        const ip = getEmptyServiceIp(network, []);
        expect(ip).to.be.equal('10.0.0.1');
        let ips = ['10.0.0.1'];
        for (let i = 2; i < 10; ++i) {

            const ip2 = getEmptyServiceIp(network, ips);
            expect(ip2).to.be.equal(`10.0.0.${i}`);
            ips.push(ip2);
        }
        // test error
        let errorOccured = false
        try {
            let ips = ['10.0.0.1'];
            for (let i = 2; i < 500; ++i) {

                const ip2 = getEmptyServiceIp(network, ips);
                ips.push(ip2);
            }
        } catch (err) {
            errorOccured = true;
        }
        expect(errorOccured).to.be.true;


    }).timeout(50000);




})



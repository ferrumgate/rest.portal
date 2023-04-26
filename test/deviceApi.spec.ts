
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { ExpressApp } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Group } from '../src/model/group';

import chaiExclude from 'chai-exclude';
import { DevicePosture } from '../src/model/authenticationProfile';
import { AuthenticationRule } from '../src/model/authenticationPolicy';

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
    const posture1: DevicePosture = {
        id: 'group1',
        name: "group1",
        isEnabled: true,
        labels: [],
        os: 'win32',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }
    const posture2: DevicePosture = {
        id: 'group2',
        name: "group2",
        isEnabled: true,
        labels: [],
        os: 'android',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }
    const posture3: DevicePosture = {
        id: 'group3',
        name: "group3",
        isEnabled: true,
        labels: [],
        os: 'darwin',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }
    let aRule: AuthenticationRule = {
        id: 'someid',
        name: 'test',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        isEnabled: true,
        networkId: 'abc',
        profile: {
            device: { postures: [posture1.id] }
        },
        userOrgroupIds: []

    };
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
    return { posture1, posture2, posture3, aRule, user1 };
}
/**
 * authenticated user group api
 */
describe('deviceApi', async () => {
    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;
    const redisService = appService.redisService;
    const sessionService = appService.sessionService;

    before(async () => {
        await expressApp.start();
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.init();
    })
    after(async () => {
        await expressApp.stop();
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        appService.configService.config.groups = [];
        appService.configService.config.networks = [];
        appService.configService.config.gateways = [];
        appService.configService.config.devicePostures = [];
        appService.configService.config.authenticationPolicy.rules = [];

        await redisService.flushAll();
    })


    it('check authorazion as admin role', async () => {
        //prepare data
        const { posture1, posture2, posture3, aRule, user1 } = createSampleData();
        const clonedUser = Util.clone(user1);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/device/posture/${posture1.id}`)
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


    it('GET /device/posture/:id returns 200', async () => {
        //prepare data
        const { posture1, posture2, posture3, aRule, user1 } = createSampleData();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveDevicePosture(posture1);
        await appService.configService.saveDevicePosture(posture2);
        await appService.configService.saveDevicePosture(posture3);
        await appService.configService.saveAuthenticationPolicyRule(aRule);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/device/posture/${posture2.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expectToDeepEqual(response.body, posture2);

    }).timeout(50000);

    it('GET /device/posture/:id returns 401', async () => {
        //prepare data
        const { posture1, posture2, posture3, aRule, user1 } = createSampleData();

        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        await appService.configService.saveDevicePosture(posture1);
        await appService.configService.saveDevicePosture(posture2);
        await appService.configService.saveDevicePosture(posture3);
        await appService.configService.saveAuthenticationPolicyRule(aRule);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/device/posture/absentGroupId`)
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


    it('GET /device/posture?search=bla returns 200', async () => {
        //prepare data
        const { posture1, posture2, posture3, aRule, user1 } = createSampleData();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        posture1.labels = ['bla'];
        await appService.configService.saveDevicePosture(posture1);
        await appService.configService.saveDevicePosture(posture2);
        await appService.configService.saveDevicePosture(posture3);
        await appService.configService.saveAuthenticationPolicyRule(aRule);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/device/posture?search=bla`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expectToDeepEqual(response.body.items[0], posture1);

    }).timeout(50000);

    it('DELETE /device/posture/:id returns 200', async () => {
        //prepare data
        const { posture1, posture2, posture3, aRule, user1 } = createSampleData();

        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveDevicePosture(posture1);
        await appService.configService.saveDevicePosture(posture2);
        await appService.configService.saveDevicePosture(posture3);
        await appService.configService.saveAuthenticationPolicyRule(aRule);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/api/device/posture/${posture3.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const itemDb = await appService.configService.getDevicePosture(posture3.id);
        expect(itemDb).not.exist;

    }).timeout(50000);


    it('PUT /device/posture returns 200', async () => {
        //prepare data
        const { posture1, posture2, posture3, aRule, user1 } = createSampleData();
        await appService.configService.saveUser(user1);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveDevicePosture(posture1);
        await appService.configService.saveDevicePosture(posture2);
        await appService.configService.saveDevicePosture(posture3);

        await appService.configService.saveAuthenticationPolicyRule(aRule);
        posture3.name = 'blabla'
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/api/device/posture`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(posture3)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const itemDb = await appService.configService.getDevicePosture(posture3.id);


        expectToDeepEqual(itemDb, posture3);

    }).timeout(50000);



    it('POST /device/posture returns 200', async () => {
        //prepare data
        const { posture1, posture2, posture3, aRule, user1 } = createSampleData();
        await appService.configService.saveUser(user1);

        await appService.configService.saveUser(user1);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        posture1.id = '';


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/api/device/posture`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(posture1)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        posture1.id = response.body.id;


        expectToDeepEqual(response.body, posture1);

    }).timeout(50000);



})



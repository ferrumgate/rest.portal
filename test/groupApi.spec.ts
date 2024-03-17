
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { ExpressApp } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Group } from '../src/model/group';



chai.use(chaiHttp);
const expect = chai.expect;


function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete b.insertDate;
    delete b.updateDate;
    expect(a).to.deep.equal(b);
}

function createSampleData() {
    const group1: Group = {
        id: 'group1',
        name: "group1",
        isEnabled: true,
        labels: [],
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }
    const group2: Group = {
        id: 'group2',
        name: "group2",
        isEnabled: true,
        labels: [],
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }
    const group3: Group = {
        id: 'group3',
        name: "group3",
        isEnabled: true,
        labels: [],
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

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
        groupIds: [group1.id]

    }
    return { group1, group2, group3, user1 };
}
/**
 * authenticated user group api
 */
describe('groupApi', async () => {
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
        await redisService.flushAll();
    })


    it('check authorazion as admin role', async () => {
        //prepare data
        const { group1, group2, group3, user1 } = createSampleData();
        const clonedUser = Util.clone(user1);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/group/${group1.id}`)
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


    it('GET /group/:id returns 200', async () => {
        //prepare data
        const { group1, group2, group3, user1 } = createSampleData();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveGroup(group1);
        await appService.configService.saveGroup(group2);
        await appService.configService.saveGroup(group3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/group/${group2.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expectToDeepEqual(response.body, group2);

    }).timeout(50000);

    it('GET /group/:id returns 401', async () => {
        //prepare data
        const { group1, group2, group3, user1 } = createSampleData();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        await appService.configService.saveGroup(group1);
        await appService.configService.saveGroup(group2);
        await appService.configService.saveGroup(group3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/group/absentGroupId`)
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


    it('GET /group?search=bla returns 200', async () => {
        //prepare data
        const { group1, group2, group3, user1 } = createSampleData();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        group1.labels = ['bla'];
        await appService.configService.saveGroup(group1);
        await appService.configService.saveGroup(group2);
        await appService.configService.saveGroup(group3);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/group?search=bla`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expectToDeepEqual(response.body.items[0], group1);

    }).timeout(50000);

    it('DELETE /group/:id returns 200', async () => {
        //prepare data
        const { group1, group2, group3, user1 } = createSampleData();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        await appService.configService.saveGroup(group1);
        await appService.configService.saveGroup(group2);
        await appService.configService.saveGroup(group3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/api/group/${group3.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const itemDb = await appService.configService.getGroup(group3.id);
        expect(itemDb).not.exist;

    }).timeout(50000);


    it('PUT /group returns 200', async () => {
        //prepare data
        const { group1, group2, group3, user1 } = createSampleData();
        await appService.configService.saveUser(user1);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        await appService.configService.saveGroup(group1);
        await appService.configService.saveGroup(group2);
        await appService.configService.saveGroup(group3);
        group3.name = 'blabla'
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/api/group`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(group3)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const itemDb = await appService.configService.getGroup(group3.id);
        if (itemDb) {
            itemDb.insertDate = group3.insertDate;
            itemDb.updateDate = group3.updateDate;
        }

        expectToDeepEqual(itemDb, group3);

    }).timeout(50000);



    it('POST /group returns 200', async () => {
        //prepare data
        const { group1, group2, group3, user1 } = createSampleData();

        await appService.configService.saveUser(user1);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        group1.id = '';

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/api/group`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(group1)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        group1.id = response.body.id;

        group1.insertDate = response.body.insertDate;
        group1.updateDate = response.body.updateDate;

        expectToDeepEqual(response.body, group1);

    }).timeout(50000);


    /* it('GET /group/users returns 200', async () => {
        //prepare data
        const { group1, group2, group3, user1 } = createSampleData();
        await appService.configService.saveGroup(group1);
        await appService.configService.saveGroup(group2);
        await appService.configService.saveGroup(group3);

        user1.groupIds = [group1.id];
        await appService.configService.saveUser(user1);
        let user2 = Util.clone(user1);
        user2.id = 'userid2';
        user2.groupIds = [group2.id];
        await appService.configService.saveUser(user2);
        let user3 = Util.clone(user1);
        user3.id = 'userid3';
        user3.groupIds = [group3.id]
        await appService.configService.saveUser(user3);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid' }, 'ferrum')

        group1.id = '';

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/group/users`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);


        expect(response.body.items).exist;
        expect(response.body.items[0].id).to.equal(user1.id);

    }).timeout(50000); */




})



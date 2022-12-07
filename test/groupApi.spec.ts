
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Group } from '../src/model/group';

import chaiExclude from 'chai-exclude';

chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);


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
                .get(`/group/${group1.id}`)
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
                .get(`/group/${group2.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).to.excluding(['insertDate', 'updateDate']).deep.equal(group2);

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
                .get(`/group/absentGroupId`)
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
                .get(`/group?search=bla`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.items[0]).to.excluding(['insertDate', 'updateDate']).deep.equal(group1);

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
                .delete(`/group/${group3.id}`)
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
                .put(`/group`)
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
        expect(itemDb).to.deep.equal(group3);

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
                .post(`/group`)
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

        expect(response.body).to.deep.equal(group1);

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
                .get(`/group/users`)
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




import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Group } from '../src/model/group';


chai.use(chaiHttp);
const expect = chai.expect;



/**
 * authenticated user api tests
 */
describe('userApiAuthenticated', async () => {
    const appService = app.appService as AppService;
    const redisService = appService.redisService;
    const sessionService = appService.sessionService;
    const user: User = {
        username: 'hamza@ferrumgate.com',

        id: 'someid',
        name: 'hamza',
        source: 'local',
        roleIds: ['Admin'],
        groupIds: ['test1'],
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
        appService.configService.config.groups = [];
        await redisService.flushAll();
    })


    it('GET /user/current will return 200', async () => {
        //prepare data
        const session = await sessionService.createSession(user, false, '1.2.3.4', 'local');
        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/user/current')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;
        expect(response.body.id).to.equal('someid');
        expect(response.body.roles).exist;
        expect(response.body.roles.length).to.equal(1);
    }).timeout(50000);



    it('GET /user/:id will return 200', async () => {
        //prepare data
        const session = await sessionService.createSession(user, false, '1.2.3.4', 'local');
        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/user/${user.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;
        expect(response.body.id).to.equal('someid');
        expect(response.body.roles).not.exist;
        expect(response.body.roleIds.length).to.equal(1);
    }).timeout(50000);


    function createSampleData() {
        const user1: User = {
            username: 'hamza1@ferrumgate.com',
            id: 'someid1',
            name: 'hamza1',
            source: 'local',
            roleIds: ['Admin'],
            groupIds: ['test1'],
            isLocked: false, isVerified: true,
            password: Util.bcryptHash('somepass'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }

        const user2: User = {
            username: 'hamza2@ferrumgate.com',
            id: 'someid2',
            name: 'hamza2',
            source: 'local',
            roleIds: ['Admin'],
            groupIds: ['test2'],
            isLocked: false, isVerified: true,
            password: Util.bcryptHash('somepass'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }



        const user3: User = {
            username: 'hamza3@ferrumgate.com',
            id: 'someid3',
            name: 'hamza3',
            source: 'google',
            roleIds: ['User'],
            groupIds: ['test2'],
            isLocked: false, isVerified: false,
            password: Util.bcryptHash('somepass'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }


        const user4: User = {
            username: 'hamza4@ferrumgate.com',
            id: 'someid4',
            name: 'hamza4',
            source: 'linkedin',
            roleIds: ['User'],
            groupIds: ['test2'],
            isLocked: true, isVerified: true,
            password: Util.bcryptHash('somepass'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }

        const user5: User = {
            username: 'hamza5@ferrumgate.com',
            id: 'someid5',
            name: 'hamza5',
            source: 'linkedin',
            roleIds: ['User'],
            groupIds: ['test2'],
            isLocked: true, isVerified: true, is2FA: true, isEmailVerified: true,
            password: Util.bcryptHash('somepass'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        return { user1, user2, user3, user4, user5 };
    }

    it('GET /user will  search return 200', async () => {
        //prepare data

        const { user1, user2, user3, user4, user5 } = createSampleData();

        await appService.configService.saveUser(user1);
        await appService.configService.saveUser(user2);
        await appService.configService.saveUser(user3);
        await appService.configService.saveUser(user4);
        await appService.configService.saveUser(user5);
        const session = await sessionService.createSession(user1, false, '1.2.3.4', 'local');


        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid1', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/user?search=hamza&page=0&pageSize=2`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;
        expect(response.body.items).exist
        expect(response.body.total).to.equal(5);
        expect(response.body.items.length).to.equal(2);
        expect(response.body.items[0].id).to.equal(user1.id);
        expect(response.body.items[1].id).to.equal(user2.id);
    }).timeout(50000);


    it('GET /user will  isVerified is2FA isEmailVerified return 200', async () => {
        //prepare data

        const { user1, user2, user3, user4, user5 } = createSampleData();
        await appService.configService.saveUser(user1);
        await appService.configService.saveUser(user2);
        await appService.configService.saveUser(user3);
        await appService.configService.saveUser(user4);
        await appService.configService.saveUser(user5);
        const session = await sessionService.createSession(user1, false, '1.2.3.4', 'local');


        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid1', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/user?isVerified=yes&is2FA=yes&isEmailVerified=yes&isLocked=true`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;
        expect(response.body.items).exist
        expect(response.body.total).to.equal(1);
        expect(response.body.items.length).to.equal(1);
        expect(response.body.items[0].id).to.equal(user5.id);

    }).timeout(50000);


    it('DELETE /user/:id will return 200', async () => {
        //prepare data
        const { user1, user2, user3, user4, user5 } = createSampleData();
        await appService.configService.saveUser(user1);
        await appService.configService.saveUser(user2);
        await appService.configService.saveUser(user3);
        await appService.configService.saveUser(user4);
        await appService.configService.saveUser(user5);
        const session = await sessionService.createSession(user1, false, '1.2.3.4', 'local');


        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid1', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/user/${user1.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const user = await appService.configService.getUserById(user1.id);
        expect(user).not.exist;

    }).timeout(50000);


    it('PUT /user will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const group: Group = {
            id: 'group1', name: 'group1', isEnabled: true, labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveGroup(group);

        const { user1, user2, user3, user4, user5 } = createSampleData();
        user1.isVerified = false;
        user1.is2FA = false;
        user1.isLocked = false;
        user1.isEmailVerified = false;
        user1.isOnlyApiKey = false;
        user1.labels = [];
        user1.groupIds = [];
        user1.roleIds = [];
        await appService.configService.saveUser(user1);

        user1.name = 'test2';
        user1.isVerified = true;
        user1.is2FA = true;
        user1.isLocked = true;
        user1.isEmailVerified = true;
        user1.isOnlyApiKey = true;
        user1.labels = ['test'];
        user1.groupIds = ['grou1', 'group1'];
        user1.roleIds = ['role1', 'Admin'];

        const session = await sessionService.createSession(user, false, '1.2.3.4', 'local');

        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/user`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(user1)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const userret = await appService.configService.getUserById(user1.id);
        expect(userret).exist;
        if (userret) {
            //these values must not changed
            expect(userret.isVerified).to.be.false;
            expect(userret.isEmailVerified).to.be.false;
            expect(userret.is2FA).to.be.false;// if only 2FA is setted then we can only set to false
            //these values must change
            expect(userret.name).to.be.equal('test2');
            expect(userret.isLocked).to.be.true;
            expect(userret.isOnlyApiKey).to.be.false;
            expect(userret.labels?.length).to.be.equal(1);
            expect(userret.roleIds?.length).to.be.equal(1);
            if (userret.roleIds)
                expect(userret.roleIds[0]).to.be.equal('Admin');
            expect(userret.groupIds.length).to.be.equal(1);
            expect(userret.groupIds[0]).to.equal('group1');
        }



    }).timeout(50000);



})




import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Group } from '../src/model/group';
import { Network } from '../src/model/network';
import { Gateway } from '../src/model/network';
import { AuthenticationRule } from '../src/model/authenticationPolicy';
import { ExpressApp } from '../src';
import { SSLCertificate } from '../src/model/cert';



chai.use(chaiHttp);
const expect = chai.expect;



/**
 * authenticated user api tests
 */
describe('userApiAuthenticated', async () => {
    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;
    const redisService = appService.redisService;
    const sessionService = appService.sessionService;
    function getSampleUser() {


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
        return user;
    }
    before(async () => {
        await expressApp.start();
        const random = Util.randomNumberString();
        await appService.configService.setConfigPath(`/tmp/rest.portal.config${random}.yaml`);
        await appService.configService.init();
    })
    after(async () => {
        await expressApp.stop();
    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        appService.configService.config.groups = [];
        appService.configService.config.authenticationPolicy.rules = [];
        appService.configService.config.networks = [];
        appService.configService.config.gateways = [];
        await redisService.flushAll();
    })


    it('GET /user/current will return 200', async () => {
        //prepare data
        const user = getSampleUser();
        const session = await sessionService.createSession(user, false, '1.2.3.4', 'local');
        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: user.id, sid: session.id }, 'ferrum')

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
        const user = getSampleUser();
        const session = await sessionService.createSession(user, false, '1.2.3.4', 'local');
        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] },
            { id: user.id, sid: session.id }, 'ferrum')

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

        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] },
            { id: user1.id, sid: session.id }, 'ferrum')

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


        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: user1.id, sid: session.id }, 'ferrum')

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


        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: user1.id, sid: session.id }, 'ferrum')

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
        const user = getSampleUser();
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

        user1.labels = [];
        user1.groupIds = [];
        user1.roleIds = [];
        await appService.configService.saveUser(user1);

        user1.name = 'test2';
        user1.isVerified = true;
        user1.is2FA = true;
        user1.isLocked = true;
        user1.isEmailVerified = true;

        user1.labels = ['test'];
        user1.groupIds = ['grou1', 'group1'];
        user1.roleIds = ['role1', 'Admin'];

        const session = await sessionService.createSession(user, false, '1.2.3.4', 'local');

        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] },
            { id: user.id, sid: session.id }, 'ferrum')

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

            expect(userret.labels?.length).to.be.equal(1);
            expect(userret.roleIds?.length).to.be.equal(1);
            if (userret.roleIds)
                expect(userret.roleIds[0]).to.be.equal('Admin');
            expect(userret.groupIds.length).to.be.equal(1);
            expect(userret.groupIds[0]).to.equal('group1');
        }



    }).timeout(50000);


    it('PUT /user/current/network will return 200', async () => {
        //prepare data
        const user = getSampleUser();
        await appService.configService.saveUser(user);

        const group: Group = {
            id: 'group1', name: 'group1', isEnabled: true, labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveGroup(group);


        const session = await sessionService.createSession(user, false, '1.2.3.4', 'local');

        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] },
            { id: user.id, sid: session.id }, 'ferrum')


        appService.configService.config.authenticationPolicy.rules = [];

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isEnabled: true
        }
        const gateway: Gateway = {
            id: '123kasdfa',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }



        appService.configService.config.networks = [net];
        appService.configService.config.gateways = [gateway];

        //rule drop
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: net.id,
            userOrgroupIds: ['someid'],
            profile: {
                is2FA: false,
                blackListIps: [],
                whiteListIps: []

            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }
        appService.configService.config.authenticationPolicy.rules = [rule];



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/user/current/network`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const result = response.body;
        expect(result.items.length).to.equal(1);



    }).timeout(50000);

    function createSampleData22() {

        const user2fa: User = {
            username: 'hamza5@ferrumgate.com',
            id: 'someid5',
            name: 'hamza5',
            source: 'local-local',
            roleIds: ['User'],
            groupIds: ['test2'],
            isLocked: false, isVerified: true, is2FA: false,
            isEmailVerified: true,

            password: Util.bcryptHash('somepass'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        return { user1: user2fa }
    }


    it('GET /user/current/2fa/rekey will return 200', async () => {
        //prepare data
        const { user1 } = createSampleData22();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession(user1, false, '1.2.3.4', 'local');


        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: user1.id, sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/user/current/2fa/rekey`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.key).exist;
        expect(response.body.t2FAKey).exist;


    }).timeout(50000);

    it('GET /user/current/2fa will return 200', async () => {
        //prepare data
        const { user1 } = createSampleData22();
        user1.twoFASecret = 'somesecret';
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession(user1, false, '1.2.3.4', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: user1.id, sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/user/current/2fa`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.is2FA).to.be.false;
        expect(response.body.key).exist;
        expect(response.body.t2FAKey).exist;
        expect(response.body.t2FAKey).to.equal('somesecret');


    }).timeout(50000);


    it('PUT /user/current/2fa will return 200', async () => {
        //prepare data
        const { user1 } = createSampleData22();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession(user1, false, '1.2.3.4', 'local');


        let token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: user1.id, sid: session.id }, 'ferrum')
        //dont change anything
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/user/current/2fa`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ is2FA: false })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);


        //change is enabled
        token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: user1.id, sid: session.id }, 'ferrum')
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/user/current/2fa`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const rkey = response.body.key;
        const t2faservice = appService.twoFAService;
        const t2token = t2faservice.generateToken(response.body.t2FAKey);

        token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: user1.id, sid: session.id }, 'ferrum')
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/user/current/2fa`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ is2FA: true, key: rkey, token: t2token })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

    }).timeout(50000);



    it('PUT /user/current/pass will return 200', async () => {
        //prepare data
        const { user1 } = createSampleData22();
        user1.password = Util.bcryptHash('Test123456');
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession(user1, false, '1.2.3.4', 'local');

        let firstpass = user1.password;
        let token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: user1.id, sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/user/current/pass`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ oldPass: 'Test123456', newPass: 'Test12345678' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        //check if password changed
        expect(appService.configService.config.users.find(x => x.id == user1.id)?.password).not.equal(firstpass);



    }).timeout(50000);


    it('GET /user/:id/sensitiveData will return 200', async () => {
        //prepare data
        const user = getSampleUser();
        user.apiKey = { key: 'akey' };
        user.cert = {
            publicCrt: 'adfaf',
            privateKey: 'asdfafa'
        } as SSLCertificate;

        const session = await sessionService.createSession(user, false, '1.2.3.4', 'local');
        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] },
            { id: user.id, sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/user/${user.id}/sensitiveData?apiKey=true&cert=true`)
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
        expect(response.body.apiKey.key).to.equal('akey');
        expect(response.body.cert).exist;
        expect(response.body.cert.publicCrt).to.equal('adfaf');
        expect(response.body.cert.privateKey).not.exist;

        /// get only api key


        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/user/${user.id}/sensitiveData?apiKey=true`)
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
        expect(response.body.apiKey.key).to.equal('akey');
        expect(response.body.cert).not.exist;

        /// get only cert


        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/user/${user.id}/sensitiveData?cert=true`)
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
        expect(response.body.apiKey).not.exist;
        expect(response.body.cert).exist;

    }).timeout(50000);


    it('PUT /user/:id/sensitiveData will return 200', async () => {
        //prepare data
        const user = getSampleUser();
        user.apiKey = { key: 'akey' };
        user.cert = {
            publicCrt: 'adfaf',
            privateKey: 'asdfafa'
        } as SSLCertificate;
        const inCerts = await appService.configService.getInSSLCertificateAll();
        const session = await sessionService.createSession(user, false, '1.2.3.4', 'local');
        await appService.configService.saveUser(user);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] },
            { id: user.id, sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/user/${user.id}/sensitiveData`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ apiKey: { key: 'newkey' } })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;
        expect(response.body.apiKey.key).not.equal('newkey');
        expect(response.body.apiKey.key.startsWith(user.id)).to.be.true;
        expect(response.body.cert).not.exist;

        //check cert

        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/user/${user.id}/sensitiveData`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ cert: { publicCrt: 'newkey', parentId: inCerts.find(x => x.category == 'auth')?.id } })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;
        expect(response.body.apiKey).not.exist;
        expect(response.body.cert.publicCrt).exist;


    }).timeout(50000)

})



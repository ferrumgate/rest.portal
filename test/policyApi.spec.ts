
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { AuthenticationRule } from '../src/model/authenticationPolicy';
import { AuthorizationRule } from '../src/model/authorizationPolicy';


chai.use(chaiHttp);
const expect = chai.expect;


function createSampleDataAuthenticaton() {


    let rule1: AuthenticationRule = {
        id: '1',
        name: "zero trust1",
        action: 'allow',
        networkId: 'networkId',
        userOrgroupIds: ['somegroupid'],
        profile: {},
        isEnabled: true


    }

    let rule2: AuthenticationRule = {
        id: '2',
        name: "zero trust2",
        action: 'allow',
        networkId: 'networkId',
        userOrgroupIds: ['somegroupid'],
        profile: {},
        isEnabled: true

    }

    let rule3: AuthenticationRule = {
        id: '3',
        name: "zero trust3",
        action: 'allow',
        networkId: 'networkId',
        userOrgroupIds: ['somegroupid'],
        profile: {},
        isEnabled: true

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
    return { rule1, rule2, rule3, user1 };
}
/**
 * authenticated user group api
 */
describe('policy', async () => {
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
        appService.configService.config.authenticationPolicy.rules = [];
        appService.configService.config.authorizationPolicy.rules = [];
        await redisService.flushAll();
    })


    it('check authorazion as admin role', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthenticaton();
        const clonedUser = Util.clone(user1);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/policy/authn/rule/${rule1.id}`)
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


    it('GET /policy/authn returns 200', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthenticaton();
        await appService.configService.saveUser(user1);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthenticationPolicyRule(rule1);
        await appService.configService.saveAuthenticationPolicyRule(rule2);
        await appService.configService.saveAuthenticationPolicyRule(rule3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/policy/authn`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.rules[0]).to.deep.equal(rule1);
        expect(response.body.rules[1]).to.deep.equal(rule2);
        expect(response.body.rules[2]).to.deep.equal(rule3);

    }).timeout(50000);

    it('GET /policy/authn/rule/:id returns 200', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthenticaton();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthenticationPolicyRule(rule1);
        await appService.configService.saveAuthenticationPolicyRule(rule2);
        await appService.configService.saveAuthenticationPolicyRule(rule3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/policy/authn/rule/${rule2.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).to.deep.equal(rule2);


    }).timeout(50000);

    it('GET /policy/authn/rule/:id returns 401', async () => {
        //prepare data
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthenticaton();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthenticationPolicyRule(rule1);
        await appService.configService.saveAuthenticationPolicyRule(rule2);
        await appService.configService.saveAuthenticationPolicyRule(rule3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/policy/authn/rule/absentId`)
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



    it('DELETE /policy/auth/rule/:id returns 200', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthenticaton();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthenticationPolicyRule(rule1);
        await appService.configService.saveAuthenticationPolicyRule(rule2);
        await appService.configService.saveAuthenticationPolicyRule(rule3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/policy/authn/rule/${rule2.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const rule = await appService.configService.getAuthenticationPolicyRule(rule2.id);
        expect(rule).not.exist;

    }).timeout(50000);


    it('PUT /policy/authn/rule returns 200', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthenticaton();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthenticationPolicyRule(rule1);
        await appService.configService.saveAuthenticationPolicyRule(rule2);
        await appService.configService.saveAuthenticationPolicyRule(rule3);
        rule2.name = 'test';
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/policy/authn/rule`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(rule2)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).to.deep.equal(rule2);

        //
        const rule = await appService.configService.getAuthenticationPolicyRule(rule2.id);
        expect(rule).to.deep.equal(rule2);

    }).timeout(50000);



    it('POST /policy/authn/rule returns 200', async () => {
        //prepare data
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthenticaton();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        //for saving 
        delete (rule1 as any).id;


        rule2.name = 'test';
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/policy/authn/rule`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(rule1)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        rule1.id = response.body.id;
        expect(response.body).to.deep.equal(rule1);



    }).timeout(50000);



    it('PUT /policy/authn/rule/pos/:id returns 200', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthenticaton();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthenticationPolicyRule(rule1);
        await appService.configService.saveAuthenticationPolicyRule(rule2);
        await appService.configService.saveAuthenticationPolicyRule(rule3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/policy/authn/rule/pos/${rule1.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ previous: 0, current: 2 })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);


        //
        const policy = await appService.configService.getAuthenticationPolicy();
        expect(policy.rules[0]).to.deep.equal(rule2);
        expect(policy.rules[1]).to.deep.equal(rule3);
        expect(policy.rules[2]).to.deep.equal(rule1);

    }).timeout(50000);


    //////////////////////////////////////////////// authorization tests ////////////////////////////////



    function createSampleDataAuthorization() {


        let rule1: AuthorizationRule = {
            id: '1',
            name: "zero trust1",

            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {
                is2FA: false, isPAM: false
            },
            serviceId: 's1',
            isEnabled: true


        }

        let rule2: AuthorizationRule = {
            id: '2',
            name: "zero trust2",

            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {
                is2FA: false, isPAM: false
            },
            serviceId: 's1',
            isEnabled: true

        }

        let rule3: AuthorizationRule = {
            id: '3',
            name: "zero trust3",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {
                is2FA: false, isPAM: false
            },
            serviceId: 's1',
            isEnabled: true

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
        return { rule1, rule2, rule3, user1 };
    }



    it('check authorization as admin role', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthorization();
        const clonedUser = Util.clone(user1);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/policy/authz/rule/${rule1.id}`)
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


    it('GET /policy/authz returns 200', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthorization();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthorizationPolicyRule(rule1);
        await appService.configService.saveAuthorizationPolicyRule(rule2);
        await appService.configService.saveAuthorizationPolicyRule(rule3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/policy/authz`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.rules[0]).to.deep.equal(rule1);
        expect(response.body.rules[1]).to.deep.equal(rule2);
        expect(response.body.rules[2]).to.deep.equal(rule3);

    }).timeout(50000);

    it('GET /policy/authz/rule/:id returns 200', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthorization();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthorizationPolicyRule(rule1);
        await appService.configService.saveAuthorizationPolicyRule(rule2);
        await appService.configService.saveAuthorizationPolicyRule(rule3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/policy/authz/rule/${rule2.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).to.deep.equal(rule2);


    }).timeout(50000);

    it('GET /policy/authz/rule/:id returns 401', async () => {
        //prepare data
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthorization();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthorizationPolicyRule(rule1);
        await appService.configService.saveAuthorizationPolicyRule(rule2);
        await appService.configService.saveAuthorizationPolicyRule(rule3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/policy/authn/rule/absentId`)
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



    it('DELETE /policy/authz/rule/:id returns 200', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthorization();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthorizationPolicyRule(rule1);
        await appService.configService.saveAuthorizationPolicyRule(rule2);
        await appService.configService.saveAuthorizationPolicyRule(rule3);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/policy/authz/rule/${rule2.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const rule = await appService.configService.getAuthorizationPolicyRule(rule2.id);
        expect(rule).not.exist;

    }).timeout(50000);


    it('PUT /policy/authz/rule returns 200', async () => {
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthorization();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        await appService.configService.saveAuthorizationPolicyRule(rule1);
        await appService.configService.saveAuthorizationPolicyRule(rule2);
        await appService.configService.saveAuthorizationPolicyRule(rule3);
        rule2.name = 'test';
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/policy/authz/rule`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(rule2)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).to.deep.equal(rule2);

        //
        const rule = await appService.configService.getAuthorizationPolicyRule(rule2.id);
        expect(rule).to.deep.equal(rule2);

    }).timeout(50000);



    it('POST /policy/authz/rule returns 200', async () => {
        //prepare data
        //prepare data
        const { rule1, rule2, rule3, user1 } = createSampleDataAuthorization();
        await appService.configService.saveUser(user1);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        //for saving 
        delete (rule1 as any).id;


        rule2.name = 'test';
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/policy/authz/rule`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(rule1)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        rule1.id = response.body.id;
        expect(response.body).to.deep.equal(rule1);



    }).timeout(50000);





})




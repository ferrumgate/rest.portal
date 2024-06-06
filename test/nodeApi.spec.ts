import chai from 'chai';
import chaiHttp from 'chai-http';
import { ExpressApp } from '../src/index';
import { Node, NodeDetail } from '../src/model/network';
import { User } from '../src/model/user';
import { AppService } from '../src/service/appService';
import { Util } from '../src/util';
import { NodeService } from '../src/service/nodeService';


chai.use(chaiHttp);
const expect = chai.expect;

function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete b.insertDate;
    delete b.updateDate;
    expect(a).to.deep.equal(b);
}

/**
 * authenticated user api tests
 */
describe('nodeApi', async () => {
    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;
    const redisService = appService.redisService;
    const sessionService = appService.sessionService;
    const nodeService = appService.nodeService;
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
        await expressApp.start();
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.init();
    })
    after(async () => {
        await expressApp.stop();

    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        appService.configService.config.networks = [];
        appService.configService.config.gateways = [];
        appService.configService.config.nodes = [];
        await redisService.flushAll();
    })

    it('check authoration as admin role', async () => {
        //prepare data
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const node: Node = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNode(node);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/node/${node.id}`)
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

    it('GET /node/:id returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const node: Node = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNode(node);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/node/${node.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expectToDeepEqual(response.body, node);

    }).timeout(50000);

    it('GET /node/:id returns 401', async () => {
        //prepare data

        await appService.configService.saveUser(user);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/node/id`)
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

    it('GET /node?search=bla returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const node: Node = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNode(node);

        const node2: Node = {
            id: Util.randomNumberString(),
            name: 'test2',
            labels: ['mest'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNode(node2);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/node?search=mest`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expectToDeepEqual(response.body.items[0], node2);

    }).timeout(50000);

    it('DELETE /node/:id returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const node: Node = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNode(node);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/api/node/${node.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const itemDb = await appService.configService.getNode(node.id);
        expect(itemDb).not.exist;

    }).timeout(50000);

    it('PUT /node returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const node: Node = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNode(node);
        node.name = 'blabla'
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/api/node`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(node)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const itemDb = await appService.configService.getNode(node.id);
        expectToDeepEqual(itemDb, node);

    }).timeout(50000);

    it('POST /node returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const node: Node = {
            id: '',
            name: 'test',
            labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/api/node`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(node)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        node.id = response.body.id;
        expectToDeepEqual(response.body, node);

    }).timeout(50000);

    it('GET /node/alive returns 200', async () => {


        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const node: NodeDetail = {
            id: '123',
            lastSeen: new Date().toISOString()
        } as unknown as NodeDetail;
        await nodeService.saveAlive(node);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/node/alive`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        const items = response.body.items;
        expectToDeepEqual(items.length, 1);

    }).timeout(50000);


    /*     it('POST /node/alive returns 200', async () => {
    
    
            await appService.configService.saveUser(user);
            const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
            const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
    
            const node: NodeDetail = {
                id: Util.randomNumberString(),
                lastSeen: new Date().toISOString()
            } as unknown as NodeDetail;
    
    
            let response: any = await new Promise((resolve: any, reject: any) => {
                chai.request(app)
                    .post(`/api/node/alive`)
                    .set(`Authorization`, `Bearer ${token}`)
                    .send(node)
                    .end((err, res) => {
                        if (err)
                            reject(err);
                        else
                            resolve(res);
                    });
            })
            expect(response.status).to.equal(200);
    
            const items = await nodeService.getAllAlive();
            expect(items.length).to.equal(1);
            const item = await nodeService.getAliveById(node.id);
            expect(item).exist;
    
    
        }).timeout(50000); */



})


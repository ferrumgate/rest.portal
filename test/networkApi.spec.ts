
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Network } from '../src/model/network';

import chaiExclude from 'chai-exclude';

chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);



/**
 * authenticated user api tests
 */
describe('networkApi', async () => {
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

        const network: Network = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            clientNetwork: '10.0.0.0/16',
            serviceNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNetwork(network);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/network/${network.id}`)
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


    it('GET /network/:id will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const network: Network = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: [],
            clientNetwork: '10.0.0.0/16',
            serviceNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNetwork(network);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/network/${network.id}`)
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
        expect(response.body).to.deep.equal(network);

    }).timeout(50000);

    it('GET /network/:id will return 401', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/network/someid`)
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



    it('GET /network/search will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const network: Network = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: ['mest'],
            clientNetwork: '10.0.0.0/16',
            serviceNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNetwork(network);




        const network2: Network = {
            id: Util.randomNumberString(),
            name: 'mest2',
            labels: [],
            clientNetwork: '10.0.0.0/16',
            serviceNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNetwork(network2);



        const network3: Network = {
            id: Util.randomNumberString(),
            name: 'est2',
            labels: [],
            clientNetwork: '10.0.0.0/16',
            serviceNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNetwork(network3);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/network?search=mest`)
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
        expect(response.body.items.length).to.equal(2);
        expect(response.body.items[0]).to.deep.equal(network);

        //test ids

        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/network?ids=${network2.id},${network.id}`)
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
        expect(response.body.items.length).to.equal(2);
        expect(response.body.items[0]).to.deep.equal(network2);

    }).timeout(50000);


    it('DELETE /network/id will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const network: Network = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: ['mest'],
            clientNetwork: '10.0.0.0/16',
            serviceNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNetwork(network);



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/network/${network.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const netdb = await appService.configService.getNetwork(network.id);
        expect(netdb).not.exist;

    }).timeout(50000);


    it('PUT /network will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const network: Network = {
            id: Util.randomNumberString(),
            name: 'test',
            labels: ['mest'],
            clientNetwork: '10.0.0.0/16',
            serviceNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNetwork(network);

        network.name = 'test2';
        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/network`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(network)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;

        network.insertDate = response.body.insertDate;
        network.updateDate = response.body.updateDate;
        expect(response.body).to.deep.equal(network);


        const netdb = await appService.configService.getNetwork(network.id);
        expect(netdb).to.deep.equal(network);

    }).timeout(50000);


    it('POST /network will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const network: Network = {
            id: '',
            name: 'test',
            labels: ['mest'],
            clientNetwork: '10.0.0.0/16',
            serviceNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await appService.configService.saveNetwork(network);


        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/network`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(network)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;
        //posting creates a new id
        network.id = response.body.id;
        network.insertDate = response.body.insertDate;
        network.updateDate = response.body.updateDate;
        expect(response.body).to.deep.equal(network);
        expect(response.body.id).exist;



    }).timeout(50000);





})



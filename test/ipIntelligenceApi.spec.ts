
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Network } from '../src/model/network';

import chaiExclude from 'chai-exclude';
import { IpIntelligence, IpIntelligenceSource } from '../src/model/IpIntelligence';
import { IpIntelligenceBWItem } from '../src/model/IpIntelligence';

chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);

function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete b.insertDate;
    delete b.updateDate;
    delete a.id;
    delete b.id;
    expect(a).to.deep.equal(b);
}

/**
 * authenticated user api tests
 */
describe('ipIntelligenceApi', async () => {
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
        appService.configService.config.ipIntelligence.blackList = [];
        appService.configService.config.ipIntelligence.whiteList = [];
        appService.configService.config.ipIntelligence.countryList = { items: [] };
        appService.configService.config.ipIntelligence.sources = [];
        await redisService.flushAll();
    })


    it('check authoration as admin role', async () => {
        //prepare data
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const bwitem: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.0.1/24',
            insertDate: new Date().toISOString(),
        }
        await appService.configService.saveIpIntelligenceBlackListItem(bwitem);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/blacklist?ids=${bwitem.id}`)
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


    it('GET /ip/intelligence/blacklist?ids= will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const bwitem: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.0.1/24',
            insertDate: new Date().toISOString(),
        }
        await appService.configService.saveIpIntelligenceBlackListItem(bwitem);


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/blacklist?ids=${bwitem.id}`)
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

        expectToDeepEqual(response.body.items[0], bwitem);

    }).timeout(50000);





    it('GET /ip/intelligence/blacklist?ip= will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const bwitem: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.0.1/24',
            insertDate: new Date().toISOString(),
        }
        await appService.configService.saveIpIntelligenceBlackListItem(bwitem);

        const bwitem2: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.1.1/24',
            insertDate: new Date().toISOString(),
        }
        await appService.configService.saveIpIntelligenceBlackListItem(bwitem2);

        const bwitem3: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.1.1/28',
            insertDate: new Date().toISOString(),
        }
        await appService.configService.saveIpIntelligenceBlackListItem(bwitem3);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/blacklist?ip=192.168.1.2`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        //console.log(response.body);
        expect(response.status).to.equal(200);
        expect(response.body).exist;
        expect(response.body.items.length).to.equal(1);

        expectToDeepEqual(response.body.items[0], bwitem2);

        //test ids

        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/blacklist?ip=192.168.3.2`)
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
        expect(response.body.items.length).to.equal(0);


    }).timeout(50000);



    it('DELETE /network/id will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const bwitem: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.0.1/24',
            insertDate: new Date().toISOString(),
        }
        await appService.configService.saveIpIntelligenceBlackListItem(bwitem);




        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/ip/intelligence/blacklist/${bwitem.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const netdb = await appService.configService.getIpIntelligenceBlackListItem(bwitem.id);
        expect(netdb).not.exist;

    }).timeout(50000);





    it('POST /ip/intelligence/blacklist will return 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const bwitem: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
        }



        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/ip/intelligence/blacklist`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ items: [bwitem] })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;


        expectToDeepEqual(response.body.results[0].item, bwitem);
        expect(response.body.results[0].item).exist;
        expect(response.body.results[0].errMsg).not.exist;


    }).timeout(50000);


    it('POST /ip/intelligence/blacklist will return with allready exists and', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const bwitem: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveIpIntelligenceBlackListItem(bwitem);



        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/ip/intelligence/blacklist`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ items: [bwitem] })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;


        expectToDeepEqual(response.body.results[0].item, bwitem);
        expect(response.body.results[0].item).exist;
        expect(response.body.results[0].errMsg).exist;


    }).timeout(50000);

    it('POST /ip/intelligence/blacklist will return with allready exists', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const bwitem: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveIpIntelligenceBlackListItem(bwitem);

        // this ip allready exits
        const bwitem2: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.0.1/32',
            insertDate: new Date().toISOString(),
        }

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/ip/intelligence/blacklist`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ items: [bwitem2] })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;


        expectToDeepEqual(response.body.results[0].item, bwitem2);
        expect(response.body.results[0].item).exist;
        expect(response.body.results[0].errMsg).exist;


    }).timeout(50000);

    it('POST /ip/intelligence/blacklist will return with allready exists', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const bwitem: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.0.0/16',
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveIpIntelligenceBlackListItem(bwitem);

        //this block allready exits
        const bwitem2: IpIntelligenceBWItem = {
            id: Util.randomNumberString(),
            val: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
        }

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/ip/intelligence/blacklist`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ items: [bwitem2] })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;


        expectToDeepEqual(response.body.results[0].item, bwitem2);
        expect(response.body.results[0].item).exist;
        expect(response.body.results[0].errMsg).exist;


    }).timeout(50000);


    //// ip intelligence source 

    it('GET /ip/intelligence/source will return items', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveIpIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/source`)
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


        expectToDeepEqual(response.body.items[0], item);



    }).timeout(50000);

    it('DELETE /ip/intelligence/source', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveIpIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/ip/intelligence/source/` + item.id)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        const items = await appService.configService.getIpIntelligenceSources();
        expect(items.length).to.equal(0);


    }).timeout(50000);

    it('POST /ip/intelligence/source', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: IpIntelligenceSource = {
            id: Util.randomNumberString(), apiKey: 'abc',
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        //await appService.configService.saveIpIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/ip/intelligence/source`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(item)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;

        const items = await appService.configService.getIpIntelligenceSources();
        expect(items.length).to.equal(1);


    }).timeout(50000);

    it('PUT /ip/intelligence/source', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: IpIntelligenceSource = {
            id: Util.randomNumberString(), apiKey: 'abc',
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveIpIntelligenceSource(item);
        item.apiKey = 'def'
        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/ip/intelligence/source`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(item)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;

        const items = await appService.configService.getIpIntelligenceSources();
        expect(items.length).to.equal(1);
        expect(items[0].apiKey).to.equal('def');

    }).timeout(50000);





})



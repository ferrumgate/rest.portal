import chai from 'chai';
import chaiHttp from 'chai-http';
import { ExpressApp } from '../src';
import { DnsRecord } from '../src/model/dns';
import { User } from '../src/model/user';
import { AppService } from '../src/service/appService';
import { Util } from '../src/util';
import { esHost, esPass, esUser } from './common.spec';

chai.use(chaiHttp);
const expect = chai.expect;

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
describe('dnsApi', async () => {
    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;
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
        await expressApp.start();
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.init();
        await appService.configService.setIsConfigured(1);
        await appService.esService.reConfigure(esHost, esUser, esPass, '1s');
        await appService.esIntelService.reConfigure(esHost, esUser, esPass, '1s');

    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        appService.configService.config.networks = [];
        appService.configService.config.gateways = [];
        appService.configService.config.ipIntelligence.sources = [];
        appService.configService.config.ipIntelligence.lists = [];
        appService.configService.config.dns.records = [];
        await redisService.flushAll();
        await appService.esService.reset();
    })
    after(async () => {
        await expressApp.stop();
    })

    it('check authoration as admin role', async () => {
        //prepare data
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: DnsRecord = {
            id: Util.randomNumberString(),
            fqdn: 'www.test.com',
            ip: '1.2.3.4',
            labels: [],
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true
        }

        await appService.configService.saveDnsRecord(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/dns/record`)
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

    //// ip intelligence source 

    it('GET /ip/dns/records will return items', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: DnsRecord = {
            id: Util.randomNumberString(),
            fqdn: 'www.test.com',
            ip: '1.2.3.4',
            labels: [],
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true
        }

        await appService.configService.saveDnsRecord(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/dns/record`)
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

    it('DELETE /dns/record', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: DnsRecord = {
            id: Util.randomNumberString(),
            fqdn: 'www.test.com',
            ip: '1.2.3.4',
            labels: [],
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true
        }

        await appService.configService.saveDnsRecord(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/api/dns/record/` + item.id)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        const items = await appService.configService.getDnsRecords();
        expect(items.length).to.equal(0);

    }).timeout(50000);

    it('POST /dns/record', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: DnsRecord = {
            id: Util.randomNumberString(),
            fqdn: 'www.test.com',
            ip: '1.2.3.4',
            labels: [],
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true
        }

        //await appService.configService.saveIpIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/api/dns/record`)
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

        const items = await appService.configService.getDnsRecords();
        expect(items.length).to.equal(1);

    }).timeout(50000);

    it('PUT /dns/source', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: DnsRecord = {
            id: Util.randomNumberString(),
            fqdn: 'www.test.com',
            ip: '1.2.3.4',
            labels: [],
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true
        }

        await appService.configService.saveDnsRecord(item);
        item.fqdn = 'www.test2.com'
        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/api/dns/record`)
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

        const items = await appService.configService.getDnsRecords();
        expect(items.length).to.equal(1);
        expect(items[0].fqdn).to.equal('www.test2.com');

    }).timeout(50000);

})


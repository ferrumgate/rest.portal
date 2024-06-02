import chai from 'chai';
import chaiHttp from 'chai-http';
import sinon from 'sinon';
import { ExpressApp } from '../src/index';
import { Gateway } from '../src/model/network';
import { User } from '../src/model/user';
import { AppService } from '../src/service/appService';
import { Util } from '../src/util';
import Axios, { AxiosRequestConfig } from 'axios';

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
describe('cloudApi', async () => {
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
    })
    after(async () => {
        await expressApp.stop();

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


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/cloud/config`)
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
    afterEach(() => {
        sinon.restore();
    });

    it('GET /cloud/config returns 200', async () => {
        //prepare data

        await appService.configService.saveUser(user);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        sinon.stub(process, 'env').value({
            FERRUM_CLOUD_ID: 'test1',
            FERRUM_CLOUD_TOKEN: 'test2',
            FERRUM_CLOUD_URL: 'test3',
            FERRUM_CLOUD_IP: 'www.google.com',
            FERRUM_CLOUD_PORT: 'test5'
        });
        sinon.stub(Util, 'resolveHostname').resolves('1.1.1.1');



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/cloud/config`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.ferrumCloudId).to.equal('test1');
        expect(response.body.ferrumCloudToken).to.equal('test2');
        expect(response.body.ferrumCloudUrl).to.equal('test3');
        expect(response.body.ferrumCloudIp).to.equal('1.1.1.1');
        expect(response.body.ferrumCloudPort).to.equal('test5');

    }).timeout(50000);



    it('GET /cloud/worker returns 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        sinon.stub(process, 'env').value({
            FERRUM_CLOUD_ID: 'test1',
            FERRUM_CLOUD_TOKEN: 'test2',
            FERRUM_CLOUD_URL: 'test3'
        });

        const workers = [
            { id: 'worker1', name: 'Worker 1' },
            { id: 'worker2', name: 'Worker 2' },
            { id: 'worker3', name: 'Worker 3' }
        ];

        sinon.stub(appService.configService, 'getFerrumCloudId').resolves('test1');
        sinon.stub(appService.configService, 'getFerrumCloudUrl').resolves('test3');
        sinon.stub(appService.configService, 'getFerrumCloudToken').resolves('test2');
        sinon.stub(appService.configService, 'getEncryptKey').resolves('encryptKey');
        sinon.stub(appService.configService, 'getRedisPass').resolves('redisPass');
        sinon.stub(appService.configService, 'getRedisIntelPass').resolves('redisIntelPass');
        sinon.stub(appService.configService, 'getEsUser').resolves('esUser');
        sinon.stub(appService.configService, 'getEsPass').resolves('esPass');
        sinon.stub(appService.configService, 'getEsIntelUser').resolves('esIntelUser');
        sinon.stub(appService.configService, 'getEsIntelPass').resolves('esIntelPass');
        sinon.stub(appService.configService, 'getClusterNodePublicKey').resolves('clusterNodePublicKey');
        sinon.stub(appService.configService, 'getFerrumCloudIp').resolves('www.google.com');
        sinon.stub(appService.configService, 'getFerrumCloudPort').resolves('test5');
        sinon.stub(Util, 'resolveHostname').resolves('1.1.1.1');

        sinon.stub(Axios, 'get').resolves({ data: { items: workers } });

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/cloud/worker`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        });

        expect(response.status).to.equal(200);
        expect(response.body).to.deep.equal({ items: workers });
    }).timeout(50000);

    it('POST /cloud/worker returns 200', async () => {
        //prepare data
        await appService.configService.saveUser(user);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        sinon.stub(process, 'env').value({
            FERRUM_CLOUD_ID: 'test1',
            FERRUM_CLOUD_TOKEN: 'test2',
            FERRUM_CLOUD_URL: 'test3'
        });

        const workers = [
            { id: 'worker1', name: 'Worker 1' },
            { id: 'worker2', name: 'Worker 2' },
            { id: 'worker3', name: 'Worker 3' }
        ];

        sinon.stub(appService.configService, 'getFerrumCloudId').resolves('test1');
        sinon.stub(appService.configService, 'getFerrumCloudUrl').resolves('test3');
        sinon.stub(appService.configService, 'getFerrumCloudToken').resolves('test2');
        sinon.stub(appService.configService, 'getEncryptKey').resolves('encryptKey');
        sinon.stub(appService.configService, 'getRedisPass').resolves('redisPass');
        sinon.stub(appService.configService, 'getRedisIntelPass').resolves('redisIntelPass');
        sinon.stub(appService.configService, 'getEsUser').resolves('esUser');
        sinon.stub(appService.configService, 'getEsPass').resolves('esPass');
        sinon.stub(appService.configService, 'getEsIntelUser').resolves('esIntelUser');
        sinon.stub(appService.configService, 'getEsIntelPass').resolves('esIntelPass');
        sinon.stub(appService.configService, 'getClusterNodePublicKey').resolves('clusterNodePublicKey');
        sinon.stub(appService.configService, 'getFerrumCloudIp').resolves('www.google.com');
        sinon.stub(appService.configService, 'getFerrumCloudPort').resolves('test5');
        sinon.stub(Util, 'resolveHostname').resolves('1.1.1.1');

        sinon.stub(Axios, 'post').resolves({ data: { items: workers } });

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/api/cloud/worker`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ workers: workers })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        });

        expect(response.status).to.equal(200);
        expect(response.body).to.deep.equal({ items: workers });
    }).timeout(50000);
});
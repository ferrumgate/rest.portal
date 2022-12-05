
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Gateway } from '../src/model/network';


chai.use(chaiHttp);
const expect = chai.expect;



/**
 * authenticated user api tests
 */
describe('summaryApi', async () => {
    const appService = app.appService as AppService;
    const redisService = appService.redisService;
    const sessionService = appService.sessionService;
    const configService = appService.configService;
    before(async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        await configService.setConfigPath(filename);
        await appService.configService.setJWTSSLCertificate({ privateKey: fs.readFileSync('./ferrumgate.com.key').toString(), publicKey: fs.readFileSync('./ferrumgate.com.crt').toString() });
    })

    beforeEach(async () => {

        configService.config.networks = [];
        configService.config.gateways = [];
        configService.config.users = [];
        configService.config.groups = [];
        configService.config.services = [];
        configService.config.authorizationPolicy.rules = [];
        configService.config.authenticationPolicy.rules = [];
        await redisService.flushAll();
        configService.config.users = [
            {
                username: 'admin',
                groupIds: [],
                id: 'admin',
                name: 'admin',
                source: 'local',
                roleIds: ['Admin'],
                isLocked: false, isVerified: true,
                password: Util.bcryptHash('ferrumgate'),
                insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString()
            },
            {
                username: 'user2',
                groupIds: [],
                id: 'user2',
                name: 'user2',
                source: 'local',
                roleIds: ['User'],
                isLocked: false, isVerified: true,
                password: Util.bcryptHash('ferrumgate'),
                insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString()
            }
        ];
    })


    it('/summary/config only admin call', async () => {

        const session = await sessionService.createSession({ id: 'user2' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'user2', sid: session.id }, 'ferrum')

        //prepare data
        await configService.saveUser({ id: 'test2' } as any);
        await configService.saveNetwork({ id: 'test4' } as any);
        await configService.saveGateway({ id: 'test4' } as any);
        await configService.saveAuthenticationPolicyRule({ id: 'test5' } as any);
        await configService.saveAuthorizationPolicyRule({ id: 'test6' } as any);
        await configService.saveService({ id: 'test7' } as any);
        await configService.saveGroup({ id: 'test10' } as any);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/config`)
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


    it('/summary/config', async () => {

        const session = await sessionService.createSession({ id: 'admin' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin', sid: session.id }, 'ferrum')

        //prepare data
        await configService.saveUser({ id: 'test2' } as any);
        await configService.saveNetwork({ id: 'test4' } as any);
        await configService.saveGateway({ id: 'test4' } as any);
        await configService.saveAuthenticationPolicyRule({ id: 'test5' } as any);
        await configService.saveAuthorizationPolicyRule({ id: 'test6' } as any);
        await configService.saveService({ id: 'test7' } as any);
        await configService.saveGroup({ id: 'test10' } as any);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/config`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.userCount).to.equal(3);

    }).timeout(50000);



    it('/summary/active only admin call', async () => {

        const session = await sessionService.createSession({ id: 'user2' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'user2', sid: session.id }, 'ferrum')

        //prepare data

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/active`)
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


    it('/summary/active', async () => {

        const session = await sessionService.createSession({ id: 'admin' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin', sid: session.id }, 'ferrum')
        await redisService.hset('/tunnel/id/test', { id: 'test' });
        await redisService.hset('/tunnel/id/test2', { id: 'test2' });

        //prepare data

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/active`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.tunnelCount).to.equal(2);
        expect(response.body.sessionCount).to.equal(1);

    }).timeout(50000);


    it('/summary/logintry', async () => {

        const session = await sessionService.createSession({ id: 'admin' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin', sid: session.id }, 'ferrum')


        //prepare data

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/logintry`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.total).exist
        expect(response.body.aggs).exist;

    }).timeout(50000);


    it('/summary/createtunnel', async () => {

        const session = await sessionService.createSession({ id: 'admin' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin', sid: session.id }, 'ferrum')
        //prepare data
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/createtunnel`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.total).exist
        expect(response.body.aggs).exist;

    }).timeout(50000);

    it('/summary/2facheck', async () => {

        const session = await sessionService.createSession({ id: 'admin' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin', sid: session.id }, 'ferrum')
        //prepare data
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/2facheck`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.total).exist
        expect(response.body.aggs).exist;

    }).timeout(50000);



    it('/summary/userloginsuccess', async () => {

        const session = await sessionService.createSession({ id: 'admin' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin', sid: session.id }, 'ferrum')
        //prepare data
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/userloginsuccess`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.total).exist
        expect(response.body.aggs).exist;

    }).timeout(50000);


    it('/summary/userloginfailed', async () => {

        const session = await sessionService.createSession({ id: 'admin' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin', sid: session.id }, 'ferrum')
        //prepare data
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/userloginfailed`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.total).exist
        expect(response.body.aggs).exist;

    }).timeout(50000);


    it('/summary/user/logintry', async () => {

        const session = await sessionService.createSession({ id: 'admin' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin', sid: session.id }, 'ferrum')
        //prepare data
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/user/logintry`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.total).exist
        expect(response.body.aggs).exist;

    }).timeout(50000);



    it('/summary/user/logintryhours', async () => {

        const session = await sessionService.createSession({ id: 'admin' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin', sid: session.id }, 'ferrum')
        //prepare data
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/summary/user/logintryhours`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.total).exist
        expect(response.body.aggs).exist;

    }).timeout(50000);







})



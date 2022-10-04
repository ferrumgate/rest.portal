
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { config } from 'process';
import { AuthSettings } from '../src/model/authSettings';
import * as twofactor from 'node-2fa';
import { Gateway } from '../src/model/network';
import { Network } from '../src/model/network';

chai.use(chaiHttp);
const expect = chai.expect;




describe('authApi ', async () => {
    const appService = (app.appService) as AppService;
    const redisService = appService.redisService;
    const configService = appService.configService;
    const user: User = {
        username: 'hamza@ferrumgate.com',
        groupIds: [],
        id: 'someid',
        name: 'hamza',
        password: Util.bcryptHash('somepass'),
        source: 'local',
        isVerified: true,
        isLocked: false,
        is2FA: true,
        twoFASecret: twofactor.generateSecret().secret,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        roleIds: []

    }

    const user2: User = {
        username: 'hamza2@ferrumgate.com',
        groupIds: [],
        id: 'someid',
        name: 'hamza',
        password: Util.bcryptHash('somepass'),
        source: 'local',
        isVerified: true,
        isLocked: false,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        roleIds: []
    }


    const net: Network = {
        id: '1ksfasdfasf',
        name: 'somenetwork',
        labels: [],
        serviceNetwork: '100.64.0.0/16',
        clientNetwork: '192.168.0.0/24'
    }
    const gateway: Gateway = {
        id: '123kasdfa',
        name: 'aserver',
        labels: [],
        networkId: net.id,
        isEnabled: 1
    }
    await configService.saveNetwork(net);
    await configService.saveGateway(gateway);
    before(async () => {
        if (fs.existsSync('/tmp/config.yaml'))
            fs.rmSync('/tmp/config.yaml')
        await configService.setConfigPath('/tmp/config.yaml');
        const auth: AuthSettings = {
            local: {
                id: Util.randomNumberString(),
                type: 'local',
                baseType: 'local',
                name: 'Local',
                tags: [],
                isForgotPassword: 0,
                isRegister: 0
            },

        }
        auth.oauth = {
            providers: [
                {
                    baseType: 'oauth',
                    type: 'google',
                    id: Util.randomNumberString(),
                    name: 'Google',
                    tags: [],
                    clientID: '920409807691-jp82nth4a4ih9gv2cbnot79tfddecmdq.apps.googleusercontent.com',
                    clientSecret: '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',
                },
                {
                    baseType: 'oauth',
                    type: 'linkedin',
                    id: Util.randomNumberString(),
                    name: 'Linkedin',
                    tags: [],
                    clientID: '866dr29tuc5uy5',
                    clientSecret: '1E3DHw0FJFUsp1Um'
                }
            ]
        }



        await configService.setAuthSettings(auth);
        await configService.setUrl('http://local.ferrumgate.com:8080')
        await configService.setJWTSSLCertificate({ privateKey: fs.readFileSync('./ferrumgate.com.key').toString(), publicKey: fs.readFileSync('./ferrumgate.com.crt').toString() });
        await configService.saveNetwork(net);
        await configService.saveGateway(gateway);
    })

    beforeEach(async () => {
        await redisService.flushAll();
        configService.config.users = [];
        await configService.saveUser(user);
        await configService.saveUser(user2);

    })
    it('POST /auth/local with 2FA result', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/local')
                .send({ username: 'hamza@ferrumgate.com', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.key).exist;
        expect(response.body.key.length).to.equal(48);
        expect(response.body.is2FA).to.be.true;


    }).timeout(50000);

    it('POST /auth/local with result 2FA false', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/local')
                .send({ username: 'hamza2@ferrumgate.com', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.key).exist;
        expect(response.body.key.length).to.equal(48);
        expect(response.body.is2FA).to.be.false;

    }).timeout(50000);


    it('POST /auth/local with result 401', async () => {

        const user5: User = {
            username: 'hamza4@ferrumgate.com',
            groupIds: [],
            id: 'someid',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: false,
            isLocked: false,
            is2FA: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/local')
                .send({ username: 'hamza4@ferrumgate.com', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);


    }).timeout(50000);

    it('POST /auth/local with result 200 and apikey', async () => {

        const user5: User = {
            username: 'hamza4@ferrumgate.com',
            groupIds: [],
            id: 'someid',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: true,
            isLocked: false,
            is2FA: true,
            apiKey: 'test',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/local')
                .set('ApiKey', 'test')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);


    }).timeout(50000);

    it('POST /auth/local with result 200 and username', async () => {

        const user5: User = {
            username: 'hx\\domain',
            groupIds: [],
            id: 'someid',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: true,
            isLocked: false,
            is2FA: true,
            apiKey: 'test',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user5);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/local')
                .send({ username: 'hx\\domain', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);


    }).timeout(50000);

    it('POST /auth/local with result 401 with empty username', async () => {



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/local')
                .send({ username: '', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);

        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/local')
                .send({ username: ' ', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);


    }).timeout(50000);



    it('POST /auth/local with result 401', async () => {

        const user6: User = {
            username: 'hamza6@ferrumgate.com',
            groupIds: [],
            id: 'someid',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: true,
            isLocked: true,
            is2FA: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        await configService.saveUser(user6);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/local')
                .send({ username: 'hamza6@ferrumgate.com', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);


    }).timeout(50000);




    it('POST /auth/local with result 401', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/local')
                .send({ username: 'hamza@ferrumgate.com', password: 'somepass222' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);


    }).timeout(50000);


    it('GET /auth/google with result 200', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/auth/google')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);


    }).timeout(50000);

    it('GET /auth/linkedin with result 200', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/auth/linkedin')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);


    }).timeout(50000);


    it('POST /auth/2fa with result 200', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/local')
                .send({ username: 'hamza@ferrumgate.com', password: 'somepass' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        const resp = response.body;
        const twoFAToken = twofactor.generateToken(user.twoFASecret || '')

        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/2fa')
                .send({ key: resp.key, twoFAToken: twoFAToken?.token })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        const resp2 = response.body;
        expect(resp2.key).exist

    }).timeout(50000);


    it('POST /authaccesstoken with result 200', async () => {

        await redisService.set(`/auth/access/test`, 'someid');
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/accesstoken')
                .send({ key: 'test' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;


    }).timeout(50000);


    it('POST /authaccesstoken with tunnel parameter with result 200', async () => {

        await redisService.set(`/auth/access/test`, 'someid');
        await redisService.hset(`/tunnel/testsession`, { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', hostId: gateway.id });
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/accesstoken')
                .send({ key: 'test', tunnelKey: 'testsession' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;

        const retVAl = await redisService.hgetAll('/tunnel/testsession');
        expect(retVAl.assignedClientIp).exist;


    }).timeout(50000);


    it('POST /auth/refreshtoken with result 200', async () => {

        await redisService.set(`/auth/access/test`, 'someid');
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/accesstoken')
                .send({ key: 'test' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;

        const refreshToken = response.body.refreshToken;
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/refreshtoken')
                .set('Authorization', `Bearer ${response.body.accessToken}`)
                .send({ refreshToken: refreshToken })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;

    }).timeout(50000);



    it('POST /auth/token/test with result 200', async () => {

        await redisService.set(`/auth/access/test`, 'someid');
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/accesstoken')
                .send({ key: 'test' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.accessToken).exist;
        expect(response.body.refreshToken).exist;

        const accessToken = response.body.accessToken;
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/auth/token/test')
                .set('Authorization', `Bearer ${accessToken}`)
                .send({ something: 'blada' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.works).to.be.true;

    }).timeout(50000);





})



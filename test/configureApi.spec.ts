
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { config } from 'process';
import { AuthSettings } from '../src/model/authSettings';
import { Tunnel } from '../src/model/tunnel';
import * as twofactor from 'node-2fa';
import { Network } from '../src/model/network';
import { Gateway } from '../src/model/network';

chai.use(chaiHttp);
const expect = chai.expect;




describe('configureApi ', async () => {
    const appService = (app.appService) as AppService;
    const redisService = appService.redisService;
    const configService = appService.configService;


    const net: Network = {
        id: '1ksfasdfasf',
        name: 'somenetwork',
        labels: [],
        clientNetwork: '10.0.0.0/24',
        serviceNetwork: '172.18.0.0/24'
    }
    const gateway: Gateway = {
        id: 'w20kaaoe',
        name: 'aserver',
        labels: [],
        networkId: net.id,
        isEnabled: true
    }

    before(async () => {
        if (fs.existsSync('/tmp/config.yaml'))
            fs.rmSync('/tmp/config.yaml')
        await configService.setConfigPath('/tmp/config.yaml');
        await appService.configService.setJWTSSLCertificate({ privateKey: fs.readFileSync('./ferrumgate.com.key').toString(), publicKey: fs.readFileSync('./ferrumgate.com.crt').toString() });

        await configService.saveNetwork(net);
        await configService.saveGateway(gateway);


    })

    beforeEach(async () => {
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
                username: 'admin2',
                groupIds: [],
                id: 'admin2',
                name: 'admin2',
                source: 'local',
                roleIds: ['Admin'],
                isLocked: false, isVerified: true,
                password: Util.bcryptHash('ferrumgate'),
                insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString()
            }
        ];



    })
    it('only admin user can callit', async () => {
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin2' }, 'ferrum')
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/configure')
                .set(`Authorization`, `Bearer ${token}`)
                .send({})
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(401);


    }).timeout(50000);


    it('configure must no be configured before', async () => {
        await configService.setIsConfigured(1);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin' }, 'ferrum')
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/configure')
                .set(`Authorization`, `Bearer ${token}`)
                .send({})
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(405);


    }).timeout(50000);


    it('sended data must be checked', async () => {
        await configService.setIsConfigured(0);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin' }, 'ferrum')
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/configure')
                .set(`Authorization`, `Bearer ${token}`)
                .send({ email: 'test@test.com' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);


    }).timeout(50000);


    it('email is not email', async () => {
        await configService.setIsConfigured(0);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin' }, 'ferrum')
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/configure')
                .set(`Authorization`, `Bearer ${token}`)
                .send({
                    email: 'test.com', password: 'somepassword',
                    url: 'https://secure.ferrumgate.com', serviceNetwork: '10.0.0.0/16',
                    clientNetwork: '172.18.18.0/24'
                })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(400);


    }).timeout(50000);

    it('is configured', async () => {
        await configService.setIsConfigured(0);
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin' }, 'ferrum')
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/configure')
                .set(`Authorization`, `Bearer ${token}`)
                .send({
                    email: 'test5@test.com', password: 'somePassword123',
                    url: 'https://secure.ferrumgate.com',
                    domain: 'ferrumgate.local',
                    serviceNetwork: '10.0.0.0/16',
                    clientNetwork: '172.18.18.0/24'
                })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const user = await configService.getUserByUsername('test5@test.com')
        expect(user).exist;
        const network = await configService.getNetworkByName('default');
        expect(network).exist;
        expect(network?.clientNetwork).to.equal('172.18.18.0/24');
        expect(network?.serviceNetwork).to.equal('10.0.0.0/16');
        const isConfigured = await configService.getIsConfigured();
        expect(isConfigured).to.equal(1);

    }).timeout(50000);









})



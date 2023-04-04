
import chai from 'chai';
import chaiHttp from 'chai-http';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Tunnel } from '../src/model/tunnel';
import * as twofactor from 'node-2fa';
import { Network } from '../src/model/network';
import { Gateway } from '../src/model/network';
import fs from 'fs';
import { config } from 'process';
import { Service } from '../src/model/service';
chai.use(chaiHttp);
const expect = chai.expect;




describe('clientApi ', async () => {
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
    const net: Network = {
        id: '1ksfasdfasf',
        name: 'somenetwork',
        labels: [],
        clientNetwork: '10.0.0.0/24',
        serviceNetwork: '172.18.0.0/24',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        isEnabled: true
    }
    const gateway: Gateway = {
        id: 'w20kaaoe',
        name: 'aserver',
        labels: [],
        networkId: net.id,
        isEnabled: true,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()
    }
    let service1: Service = {
        id: Util.randomNumberString(),
        name: 'mysql-dev',
        isEnabled: true,
        labels: [],
        host: '1.2.3.4',
        networkId: net.id,
        tcp: 3306,
        protocol: 'dns',
        isSystem: true,
        assignedIp: '10.0.0.1',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        count: 1


    }

    before(async () => {


    })


    beforeEach(async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        await configService.setConfigPath(filename);
        await configService.init();
        await configService.saveNetwork(net);
        await configService.saveGateway(gateway);
        await configService.saveService(service1);
        await redisService.flushAll();
        configService.config.users = [];
        await configService.saveUser(user);
        configService.config.authenticationPolicy.rules = [];


    })
    it('GET /client/tunnel/ip', async () => {
        const tunnel: Tunnel = {
            id: 'akey', assignedClientIp: '10.0.0.1',
            authenticatedTime: new Date().toISOString(),
            clientIp: '192.168.8.8', tun: 'tun0',
            userId: user.id, gatewayId: gateway.id,
            serviceNetwork: '172.18.0.0/24',
            is2FA: true, trackId: 3
        };
        await redisService.hset('/tunnel/id/akey', tunnel)
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/client/tunnel/ip')
                .set('TunnelKey', 'akey')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.assignedIp).to.equal(tunnel.assignedClientIp);
        expect(response.body.serviceNetwork).to.equal('172.18.0.0/24');
        expect(response.body.resolvSearch).to.equal(`${net.name}.${await configService.getDomain()}`);
        expect(response.body.resolvIp).to.equal(service1.assignedIp);

    }).timeout(50000);


    it('POST /client/tunnel/confirm', async () => {
        const tunnel: Tunnel = {
            id: 'akey', assignedClientIp: '10.0.0.1',
            authenticatedTime: new Date().toISOString(),
            clientIp: '192.168.8.8', tun: 'tun0',
            userId: user.id, gatewayId: '1234',
            serviceNetwork: '192.168.0.0/24',
            is2FA: true, trackId: 5
        };
        await redisService.sadd('/clientNetwork/used', '10.0.0.1');
        // first get 
        await redisService.hset('/tunnel/id/akey', tunnel)
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/client/tunnel/confirm')
                .set('TunnelKey', 'akey')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        //const result = await redisService.sismember(`/tunnel/configure/${tunnel.gatewayId}`, 'akey');
        //expect(result == 1).to.be.true;

    }).timeout(50000);


    it('POST /client/tunnel', async () => {
        await appService.configService.saveAuthenticationPolicyRule({
            id: '123', isEnabled: true, name: 'test', networkId: net.id, profile: {}, userOrgroupIds: [user.id], updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()
        })
        const session = await appService.sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        await redisService.hset(`/tunnel/id/kq0gxvko3j2v5tarpp9s8jsn5faxqd4knr0vplwhtiey3m2jo8k3dux2nvfem5sa`, {
            id: `kq0gxvko3j2v5tarpp9s8jsn5faxqd4knr0vplwhtiey3m2jo8k3dux2nvfem5sa`,
            clientIp: '1234', gatewayId: gateway.id
        })
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/client/tunnel')
                .set(`Authorization`, `Bearer ${token}`)
                .send({ tunnelKey: 'kq0gxvko3j2v5tarpp9s8jsn5faxqd4knr0vplwhtiey3m2jo8k3dux2nvfem5sa' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        const result = await redisService.hgetAll(`/tunnel/id/kq0gxvko3j2v5tarpp9s8jsn5faxqd4knr0vplwhtiey3m2jo8k3dux2nvfem5sa`);
        expect(result.id).exist;

    }).timeout(50000);











})



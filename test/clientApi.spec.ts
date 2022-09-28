
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
        serviceNetwork: '172.18.0.0/24'
    }
    const gateway: Gateway = {
        id: 'w20kaaoe',
        name: 'aserver',
        labels: [],
        networkId: net.id,
        isEnabled: 1
    }

    before(async () => {
        if (fs.existsSync('/tmp/config.yaml'))
            fs.rmSync('/tmp/config.yaml')
        await configService.setConfigPath('/tmp/config.yaml');


        await configService.setNetwork(net);
        await configService.setGateway(gateway);


    })

    beforeEach(async () => {
        await redisService.flushAll();
        configService.config.users = [];
        await configService.saveUser(user);


    })
    it('GET /client/tunnel/ip', async () => {
        const tunnel: Tunnel = {
            id: 'akey', assignedClientIp: '10.0.0.1',
            authenticatedTime: new Date().toISOString(),
            clientIp: '192.168.8.8', tun: 'tun0',
            userId: user.id, hostId: gateway.id,
            serviceNetwork: '192.168.0.0/24'
        };
        await redisService.hset('/tunnel/akey', tunnel)
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

    }).timeout(50000);


    it('POST /client/tunnel/confirm', async () => {
        const tunnel: Tunnel = {
            id: 'akey', assignedClientIp: '10.0.0.1',
            authenticatedTime: new Date().toISOString(),
            clientIp: '192.168.8.8', tun: 'tun0',
            userId: user.id, hostId: '1234',
            serviceNetwork: '192.168.0.0/24'
        };
        await redisService.sadd('/clientNetwork/used', '10.0.0.1');
        // first get 
        await redisService.hset('/tunnel/akey', tunnel)
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
        const result = await redisService.sismember(`/tunnel/configure/${tunnel.hostId}`, 'akey');
        expect(result == 1).to.be.true;

    }).timeout(50000);











})



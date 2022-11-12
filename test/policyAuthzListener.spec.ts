
//docker run --net=host --name redis --rm -d redis


import chai, { util } from 'chai';
import chaiHttp from 'chai-http';
import { Util } from '../src/util';

import { SystemWatcherService } from '../src/service/system/systemWatcherService';
import { Tunnel } from '../src/model/tunnel';
import { watch } from 'fs';
import { RedisService, RedisServiceManuel } from '../src/service/redisService';
import { PolicyAuthzListener, PolicyRoomService } from '../src/service/system/policyAuthzListener';
import { ConfigService } from '../src/service/configService';
import { PolicyAuthzResult, PolicyService } from '../src/service/policyService';
import { TunnelService } from '../src/service/tunnelService';
import { AuditService } from '../src/service/auditService';
import { executionAsyncId } from 'async_hooks';




chai.use(chaiHttp);
const expect = chai.expect;

describe('policyRoomService', () => {
    beforeEach(async () => {
        try {
            const simpleRedis = new RedisServiceManuel('localhost:6379');
            await simpleRedis.flushAll();

        } catch (err) {

        }
    })

    function createTunnel(): Tunnel {
        return {
            id: Util.randomNumberString(64), userId: Util.randomNumberString(), authenticatedTime: new Date().toString(),
            assignedClientIp: '10.0.0.3', trackId: Math.floor(Math.random() * 4000000000),
            clientIp: '192.168.1.100', tun: 'tun0', hostId: '1234', serviceNetwork: '192.168.0.0/24'
        }
    }

    it('start/stop', async () => {

        const room = new PolicyRoomService('1233', '344', '2342');
        await room.start();
        await room.stop();

    }).timeout(2000);

    it('push delete, push ok', async () => {
        const simpleRedis = new RedisServiceManuel('localhost:6379', undefined, 'single');
        const room = new PolicyRoomService('1233', '344', '23421');
        await room.start();
        await room.pushDelete(15);
        await room.pushOk();
        await Util.sleep(2000);
        const result = await simpleRedis.xread(room.redisStreamKey, 10, '0', 1000);
        expect(result.length).to.equal(2);
        expect(result[0].cmd).exist;
        expect(result[0].cmd.includes('1/delete/15')).to.be.true;
        expect(result[1].cmd.includes('2/ok')).to.be.true;
        await room.stop();

    }).timeout(5000)

    it('reset', async () => {
        const simpleRedis = new RedisServiceManuel('localhost:6379', undefined, 'single');
        const room = new PolicyRoomService('1233', '344', '23422');

        await room.pushDelete(15);
        await room.pushOk();
        expect(room.commandList.length).to.equal(2);
        await room.pushReset();
        expect(room.commandList.length).to.equal(1);
        await room.start();
        await Util.sleep(2000);
        const result = await simpleRedis.xread(room.redisStreamKey, 10, '0', 1000);
        expect(result.length).to.equal(1);
        expect(result[0].cmd).exist;
        expect(result[0].cmd.includes('1/reset')).to.be.true;
        await room.stop();

    }).timeout(5000)


    it('push', async () => {
        const simpleRedis = new RedisServiceManuel('localhost:6379', undefined, 'single');
        const room = new PolicyRoomService('1233', '344', '223422');
        await room.start();
        await room.push(12, { error: 1 });
        await room.push(13, { error: 0, index: 1, rule: { id: 'abc' } as any });
        await room.push(14, { error: 2, rule: { id: 'abcd' } as any });

        await Util.sleep(2000);
        const result = await simpleRedis.xread(room.redisStreamKey, 10, '0', 1000);
        expect(result.length).to.equal(3);
        expect(result[0].cmd).exist;

        expect(result[0].cmd.includes('1/update/12/1/0/10001/')).to.be.true;

        expect(result[1].cmd.includes('2/update/13/0/1/10000/abc')).to.be.true;

        expect(result[2].cmd.includes('3/update/14/1/0/10002/abcd')).to.be.true;

        await room.stop();

    }).timeout(5000)




})



describe('policyAuthzListener', () => {
    beforeEach(async () => {

        const simpleRedis = new RedisServiceManuel('localhost:6379');
        await simpleRedis.flushAll();


    })

    function createTunnel(trackId?: number, hostId?: string): Tunnel {
        return {
            id: Util.randomNumberString(64), userId: Util.randomNumberString(), authenticatedTime: new Date().toString(),
            assignedClientIp: '10.0.0.3', trackId: trackId || Math.floor(Math.random() * 4000000000),
            clientIp: '192.168.1.100', tun: 'tun0', hostId: hostId || '1234', serviceNetwork: '192.168.0.0/24'
        }
    }

    function createNeeds() {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const redisService = new RedisService("localhost:6379");
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];
        const tunnelService = new TunnelService(configService, redisService);
        const auditService = new AuditService();
        let policyService = new PolicyService(configService, tunnelService, auditService);
        return { simpleRedis: redisService, configService: configService, policyService: policyService, tunnelService: tunnelService, auditService: auditService, };
    }

    it('publish i am alive', async () => {

        const { simpleRedis, configService, policyService } = createNeeds();
        const systemWatcher = new SystemWatcherService();
        const policy = new PolicyAuthzListener(policyService, systemWatcher);
        policy.start();
        await Util.sleep(1000);
        await simpleRedis.publish('/policy/service', 'alive/ab/cd/ef');
        await Util.sleep(5000);
        await policy.stop();
        const item = await simpleRedis.hgetAll('/service/ab/cd/ef')
        expect(item.lastSeen).to.exist;


    }).timeout(200000)

    it('fillRoomService', async () => {

        const { simpleRedis, configService, policyService } = createNeeds();
        const systemWatcher = new SystemWatcherService();
        const tunnel1 = createTunnel(1234, 'abcd');
        const tunnel2 = createTunnel(1234, 'abcde');
        systemWatcher.tunnels.set(tunnel1.id || '0', tunnel1);
        systemWatcher.tunnels.set(tunnel2.id || '0', tunnel2);
        const policy = new PolicyAuthzListener(policyService, systemWatcher);

        class Room2 extends PolicyRoomService {
            isPushed = 0;
            async push(trackId: number, result: PolicyAuthzResult): Promise<void> {
                this.isPushed++;
            }
        }
        const room = new Room2('abcd', '1234', 'askdjfa');
        await policy.fillRoomService(room);
        expect(room.isPushed).to.equal(1);


    }).timeout(200000)


    it('replicate', async () => {

        const { simpleRedis, configService, policyService } = createNeeds();
        const systemWatcher = new SystemWatcherService();
        const tunnel1 = createTunnel(1234, 'abcd');
        const tunnel2 = createTunnel(1234, 'abcde');
        //systemWatcher.tunnels.set(tunnel1.id || '0', tunnel1);
        //systemWatcher.tunnels.set(tunnel2.id || '0', tunnel2);
        const policy = new PolicyAuthzListener(policyService, systemWatcher);

        await policy.replicate('abcd', '1234', 'wsdwd');
        expect(await policy.getRoom('abcd', '1234', 'wsdwd')).exist;
        //check reset command
        class Room2 extends PolicyRoomService {
            isPushed = 0;
            isPushedReset = 0;
            async push(trackId: number, result: PolicyAuthzResult): Promise<void> {
                this.isPushed++;
            }
            async pushReset(): Promise<void> {
                this.isPushedReset++;
            }
        }
        const room = new Room2('abcd', '1234', 'askdjfa');
        await policy.addRoom(room);
        await policy.replicate(room.hostId, room.serviceId, room.instanceId);
        expect(room.isPushedReset).to.equal(1);




    }).timeout(200000)


    it('policyCalculate', async () => {

        const { simpleRedis, configService, policyService } = createNeeds();
        const systemWatcher = new SystemWatcherService();

        const policy = new PolicyAuthzListener(policyService, systemWatcher);

        //check reset command
        class Room2 extends PolicyRoomService {
            isPushed = 0;
            isPushedReset = 0;
            isPushedDelete = 0;
            async push(trackId: number, result: PolicyAuthzResult): Promise<void> {
                this.isPushed++;
            }
            async pushReset(): Promise<void> {
                this.isPushedReset++;
            }
            async pushDelete(trackId: number) {
                this.isPushedDelete++;
            }
        }
        policy.setHostId('abcd');
        const room1 = new Room2('abcd', '1234', 'askdjfa');
        await policy.addRoom(room1);


        const room2 = new Room2('abcde', '12345', 'abdask');
        await policy.addRoom(room2);

        await policy.policyCalculate({ action: 'reset' });
        expect(room1.isPushedReset).to.equal(1);
        expect(room2.isPushedReset).to.equal(1);

        await policy.policyCalculate({ action: 'delete', tunnel: { hostId: 'abcdefsd', trackId: 10 } });
        expect(room1.isPushedReset).to.equal(1);
        expect(room2.isPushedReset).to.equal(1);
        expect(room1.isPushedDelete).to.equal(0);
        expect(room2.isPushedDelete).to.equal(0);


        await policy.policyCalculate({ action: 'delete', tunnel: { hostId: 'abcd', trackId: 10 } });
        expect(room1.isPushedReset).to.equal(1);
        expect(room2.isPushedReset).to.equal(1);
        expect(room1.isPushedDelete).to.equal(1);
        expect(room2.isPushedDelete).to.equal(0);
        expect(room1.isPushed).to.equal(0);
        expect(room2.isPushed).to.equal(0);


        await policy.policyCalculate({ action: 'update', tunnel: { hostId: 'abcd', trackId: 10 } });
        expect(room1.isPushedReset).to.equal(1);
        expect(room2.isPushedReset).to.equal(1);
        expect(room1.isPushedDelete).to.equal(1);
        expect(room2.isPushedDelete).to.equal(0);
        expect(room1.isPushed).to.equal(1);
        expect(room2.isPushed).to.equal(0);



    }).timeout(200000)








})
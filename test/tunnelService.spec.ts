
//docker run --net=host --name redis --rm -d redis


import chai from 'chai';
import chaiHttp from 'chai-http';
import { TunnelService } from '../src/service/tunnelService';
import { ConfigService } from '../src/service/configService';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';
import { User } from '../src/model/user';
import { Tunnel } from '../src/model/tunnel';




chai.use(chaiHttp);
const expect = chai.expect;


describe('tunnelService', () => {
    const simpleRedis = new RedisService('localhost:6379,localhost:6390');

    beforeEach(async () => {

        await simpleRedis.flushAll();

    })

    it('getEmptyIp will return an ip', async () => {
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService.setConfigPath('/tmp/rest.portal.config.yaml');
        const tunnel = new TunnelService(configService);
        const ip = await tunnel.getEmptyIp(simpleRedis);
        expect(ip).exist;
        const ipstr = Util.bigIntegerToIp(ip);
        expect(ipstr).to.equal('100.64.0.1');

    }).timeout(10000)

    it('getEmptyIp will throw because of finished ip pool', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');
        await configService2.setClientNetwork('192.168.0.0/24')
        for (let i = 0; i < 255; ++i)
            await simpleRedis.sadd('/clientNetwork/used', `192.168.0.${i}`);
        let isError = false;
        try {
            const tunnel = new TunnelService(configService2);
            const ip = await tunnel.getEmptyIp(simpleRedis);
        } catch (err) {
            isError = true;
        }
        expect(isError).to.be.true;

    }).timeout(10000)

    it('create tunnel will throw exception because of not found session', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');
        await configService2.setClientNetwork('192.168.0.0/24')
        const tunnel = new TunnelService(configService2);
        const user: User = { id: 'adfaf' } as User;

        //
        let isError = false;
        try {
            await tunnel.createTunnel(user, simpleRedis, 'randomtunnelid');
        } catch (err) { isError = true; };
        expect(isError).to.be.true;


    }).timeout(10000)

    it('create tunnel will return with out error', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');
        await configService2.setClientNetwork('192.168.0.0/24')
        const tunnel = new TunnelService(configService2);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/randomtunnelid`, { id: 'randomtunnelid', clientIp: '192.168.1.100' })
        //


        await tunnel.createTunnel(user, simpleRedis, 'randomtunnelid');
        //check every redis data 
        const ipExits = await simpleRedis.sismember(`/clientNetwork/used`, '192.168.0.1');
        expect(ipExits == 1).to.be.true;
        //ip
        expect(Util.bigIntegerToIp(tunnel.lastUsedIp)).to.equal('192.168.0.1');
        //client ip 
        const tunnelId = await simpleRedis.get('/tunnel/192.168.0.1', false)
        expect(tunnelId).to.equal('randomtunnelid');

        //tunnel
        const session = await simpleRedis.hgetAll(`/tunnel/randomtunnelid`);
        expect(session.id).to.equal('randomtunnelid');
        expect(session.authenticatedTime).exist;
        expect(session.assignedClientIp).to.equal('192.168.0.1');


    }).timeout(10000)


    it('renewIp', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');
        await configService2.setClientNetwork('192.168.0.0/24')
        const tunnel = new TunnelService(configService2);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/randomtunnelid`, { id: 'randomtunnelid', clientIp: '192.168.1.100', tun: 'tun0' })
        //


        await tunnel.createTunnel(user, simpleRedis, 'randomtunnelid');
        await tunnel.renewIp('randomtunnelid', simpleRedis);

        let exists = await simpleRedis.sismember('/clientNetwork/used', '192.168.0.1');
        expect(exists == 1).to.be.false;

        exists = await simpleRedis.sismember('/clientNetwork/used', '192.168.0.2');
        expect(exists == 1).to.be.true;

        const newtunnel: Tunnel = await simpleRedis.hgetAll('/tunnel/randomtunnelid');
        expect(newtunnel.assignedClientIp).to.equal('192.168.0.2');


    }).timeout(10000)


    it('confirm', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');
        await configService2.setClientNetwork('192.168.0.0/24')
        const tunnel = new TunnelService(configService2);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/randomtunnelid`, { id: 'randomtunnelid', clientIp: '192.168.1.100', tun: 'tun0' })
        //


        await tunnel.createTunnel(user, simpleRedis, 'randomtunnelid');
        await tunnel.confirm('randomtunnelid', simpleRedis);

        let exists = await simpleRedis.sismember('/tunnel/configure', 'randomtunnelid');
        expect(exists == 1).to.be.true;


    }).timeout(10000)


    it('alive', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');
        await configService2.setClientNetwork('192.168.0.0/24')
        const tunnel = new TunnelService(configService2);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/randomtunnelid`, { id: 'randomtunnelid', userId: 100, authenticatedTime: new Date().toString(), assignedClientIp: '10.0.0.3', clientIp: '192.168.1.100', tun: 'tun0' })
        await simpleRedis.set(`/tunnel/10.0.0.3`, 'randomtunnelid');

        await tunnel.alive('randomtunnelid', simpleRedis);

        let ttl1 = await simpleRedis.ttl('/tunnel/randomtunnelid');
        expect(ttl1).to.be.greaterThan(2 * 60 * 1000);

        let ttl2 = await simpleRedis.ttl('/tunnel/10.0.0.3');
        expect(ttl2).to.be.greaterThan(2 * 60 * 1000);


    }).timeout(10000)





})
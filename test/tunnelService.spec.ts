
//docker run --net=host --name redis --rm -d redis


import chai from 'chai';
import chaiHttp from 'chai-http';
import { TunnelService } from '../src/service/tunnelService';
import { ConfigService } from '../src/service/configService';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';
import { User } from '../src/model/user';
import { Tunnel } from '../src/model/tunnel';
import { Gateway, Network } from '../src/model/network';




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
        await configService.setNetwork(net);
        await configService.setGateway(gateway);

        const tunnel = new TunnelService(configService);
        const { network, ip } = await tunnel.getEmptyIp(simpleRedis, gateway.id);
        expect(network).exist;
        expect(ip).exist;
        const ipstr = Util.bigIntegerToIp(ip);
        expect(ipstr).to.equal('192.168.0.1');

    }).timeout(10000)

    it('getEmptyIp will throw because of finished ip pool', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');

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
            networkId: net.id
        }
        await configService2.setNetwork(net);
        await configService2.setGateway(gateway);


        for (let i = 0; i < 255; ++i)
            await simpleRedis.set(`/client/192.168.0.${i}`, i);
        let isError = false;
        try {
            const tunnel = new TunnelService(configService2);
            const ip = await tunnel.getEmptyIp(simpleRedis, gateway.id);
        } catch (err) {
            isError = true;
        }
        expect(isError).to.be.true;

    }).timeout(10000)

    it('create tunnel will throw exception because of not found session', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');

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
        await configService2.setNetwork(net);
        await configService2.setGateway(gateway);


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

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24'
        }
        const gateway: Gateway = {
            id: 'w20kaaoe',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: 1
        }
        await configService2.setNetwork(net);
        await configService2.setGateway(gateway);

        const tunnel = new TunnelService(configService2);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/randomtunnelid`, {
            id: 'randomtunnelid',
            clientIp: '192.168.1.100', tun: 'ferrumaweds', hostId: 'w20kaaoe'
        })
        //


        await tunnel.createTunnel(user, simpleRedis, 'randomtunnelid');
        //check every redis data 
        const ipExits = await simpleRedis.containsKey(`/client/192.168.0.1`);
        expect(ipExits).to.be.true;

        //ip
        const lastUsedIp = tunnel.lastUsedIps.get(net.id) || BigInt(1);
        expect(Util.bigIntegerToIp(lastUsedIp)).to.equal('192.168.0.1');
        //client ip 
        const tunnelId = await simpleRedis.get('/client/192.168.0.1', false)
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

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24'
        }
        const gateway: Gateway = {
            id: '1234',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: 1
        }
        await configService2.setNetwork(net);
        await configService2.setGateway(gateway);


        const tunnel = new TunnelService(configService2);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/randomtunnelid`, { id: 'randomtunnelid', clientIp: '192.168.1.100', tun: 'tun0', hostId: '1234' })
        //


        await tunnel.createTunnel(user, simpleRedis, 'randomtunnelid');
        await tunnel.renewIp('randomtunnelid', simpleRedis);

        let exists = await simpleRedis.containsKey('/client/192.168.0.1');
        expect(exists).to.be.false;

        exists = await simpleRedis.containsKey('/client/192.168.0.2');
        expect(exists).to.be.true;

        const newtunnel: Tunnel = await simpleRedis.hgetAll('/tunnel/randomtunnelid');
        expect(newtunnel.assignedClientIp).to.equal('192.168.0.2');


    }).timeout(10000)


    it('confirm', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24'
        }
        const gateway: Gateway = {
            id: '12345',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: 1
        }
        await configService2.setNetwork(net);
        await configService2.setGateway(gateway);


        const tunnel = new TunnelService(configService2);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/randomtunnelid`,
            { id: 'randomtunnelid', clientIp: '192.168.1.100', tun: 'tun0', hostId: '12345' })
        //


        await tunnel.createTunnel(user, simpleRedis, 'randomtunnelid');
        await tunnel.confirm('randomtunnelid', simpleRedis);
        //check every redis data 
        const hostExits = await simpleRedis.containsKey(`/host/12345/tun/tun0`);
        expect(hostExits).to.be.true

        let exists = await simpleRedis.sismember(`/tunnel/configure/12345`, 'randomtunnelid');
        expect(exists == 1).to.be.true;


    }).timeout(10000)


    it('alive', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24'
        }
        const gateway: Gateway = {
            id: '1234',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: 1
        }
        await configService2.setNetwork(net);
        await configService2.setGateway(gateway);

        const tunnel = new TunnelService(configService2);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/randomtunnelid`,
            {
                id: 'randomtunnelid', userId: 100, authenticatedTime: new Date().toString(),
                assignedClientIp: '10.0.0.3',
                clientIp: '192.168.1.100', tun: 'tun0', hostId: '1234', serviceNetwork: '192.168.0.0/24'
            })
        await simpleRedis.set(`/client/10.0.0.3`, 'randomtunnelid');
        await simpleRedis.set(`/host/1234/tun/tun0`, 'randomtunnelid');

        await tunnel.alive('randomtunnelid', simpleRedis);

        let ttl1 = await simpleRedis.ttl('/tunnel/randomtunnelid');
        expect(ttl1).to.be.greaterThan(2 * 60 * 1000);

        ttl1 = await simpleRedis.ttl('/client/10.0.0.3');
        expect(ttl1).to.be.greaterThan(2 * 60 * 1000);

        ttl1 = await simpleRedis.ttl('/host/1234/tun/tun0');
        expect(ttl1).to.be.greaterThan(2 * 60 * 1000);


    }).timeout(10000)





})

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
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        const gateway: Gateway = {
            id: '123kasdfa',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await configService.saveNetwork(net);
        await configService.saveGateway(gateway);

        const tunnel = new TunnelService(configService, simpleRedis);
        const { network, ip } = await tunnel.getEmptyIp(gateway.id);
        expect(network).exist;
        expect(ip).exist;
        const ipstr = Util.bigIntegerToIp(ip);
        expect(ipstr).to.equal('192.168.0.1');

    }).timeout(10000)
    it('getEmptyTrackId will return an trackId', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);



        const tunnel = new TunnelService(configService, simpleRedis);
        for (let i = 1; i < 100; ++i) {
            const { trackId } = await tunnel.getEmptyTrackId();
            expect(trackId).exist;
            expect(trackId).to.equal(i);
            tunnel.lastUsedTrackId = i;
        }



    }).timeout(10000)

    it('getEmptyIp will throw because of finished ip pool', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);


        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        const gateway: Gateway = {
            id: '123kasdfa',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await configService2.saveNetwork(net);
        await configService2.saveGateway(gateway);


        for (let i = 0; i < 255; ++i)
            await simpleRedis.set(`/tunnel/ip/192.168.0.${i}`, i);
        let isError = false;
        try {
            const tunnel = new TunnelService(configService2, simpleRedis);
            const ip = await tunnel.getEmptyIp(gateway.id);
        } catch (err) {
            isError = true;
        }
        expect(isError).to.be.true;

    }).timeout(10000)

    it('create tunnel will throw exception because of not found session', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);


        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        const gateway: Gateway = {
            id: '123kasdfa',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await configService2.saveNetwork(net);
        await configService2.saveGateway(gateway);


        const tunnel = new TunnelService(configService2, simpleRedis);
        const user: User = { id: 'adfaf' } as User;

        //
        let isError = false;
        try {
            await tunnel.createTunnel(user, 'randomtunnelid');
        } catch (err) { isError = true; };
        expect(isError).to.be.true;


    }).timeout(10000)

    it('create tunnel will return with out error', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);


        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
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
        await configService2.saveNetwork(net);
        await configService2.saveGateway(gateway);

        const tunnel = new TunnelService(configService2, simpleRedis);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/id/randomtunnelid`, {
            id: 'randomtunnelid',
            clientIp: '192.168.1.100', tun: 'ferrumaweds', gatewayId: 'w20kaaoe', trackId: '12'
        })
        //


        await tunnel.createTunnel(user, 'randomtunnelid');
        //check every redis data 
        const ipExits = await simpleRedis.containsKey(`/tunnel/ip/192.168.0.1`);
        expect(ipExits).to.be.true;

        //ip
        const lastUsedIp = tunnel.lastUsedIps.get(net.id) || BigInt(1);
        expect(Util.bigIntegerToIp(lastUsedIp)).to.equal('192.168.0.1');
        //client ip 
        const tunnelId = await simpleRedis.get('/tunnel/ip/192.168.0.1', false)
        expect(tunnelId).to.equal('randomtunnelid');

        //tunnel
        const session = await simpleRedis.hgetAll(`/tunnel/id/randomtunnelid`);
        expect(session.id).to.equal('randomtunnelid');
        expect(session.authenticatedTime).exist;
        expect(session.assignedClientIp).to.equal('192.168.0.1');


    }).timeout(10000)


    it('renewIp', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);


        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        const gateway: Gateway = {
            id: '1234',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await configService2.saveNetwork(net);
        await configService2.saveGateway(gateway);


        const tunnel = new TunnelService(configService2, simpleRedis);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/id/randomtunnelid`, { id: 'randomtunnelid', trackId: '12', clientIp: '192.168.1.100', tun: 'tun0', gatewayId: '1234' })
        //


        await tunnel.createTunnel(user, 'randomtunnelid');
        await tunnel.renewIp('randomtunnelid');

        let exists = await simpleRedis.containsKey('/tunnel/ip/192.168.0.1');
        expect(exists).to.be.false;

        exists = await simpleRedis.containsKey('/tunnel/ip/192.168.0.2');
        expect(exists).to.be.true;

        const newtunnel: Tunnel = await simpleRedis.hgetAll('/tunnel/id/randomtunnelid');
        expect(newtunnel.assignedClientIp).to.equal('192.168.0.2');


    }).timeout(10000)


    it('confirm', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);


        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        const gateway: Gateway = {
            id: '12345',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await configService2.saveNetwork(net);
        await configService2.saveGateway(gateway);


        const tunnel = new TunnelService(configService2, simpleRedis);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/id/randomtunnelid`,
            { id: 'randomtunnelid', clientIp: '192.168.1.100', tun: 'tun0', gatewayId: '12345', trackId: '12' })
        //


        await tunnel.createTunnel(user, 'randomtunnelid');
        await tunnel.confirm('randomtunnelid');
        //check every redis data 
        const hostExits = await simpleRedis.containsKey(`/gateway/12345/tun/tun0`);
        expect(hostExits).to.be.true

        let exists = await simpleRedis.sismember(`/tunnel/configure/12345`, 'randomtunnelid');
        expect(exists == 1).to.be.true;


    }).timeout(10000)


    it('alive', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);


        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        const gateway: Gateway = {
            id: '1234',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await configService2.saveNetwork(net);
        await configService2.saveGateway(gateway);

        const tunnel = new TunnelService(configService2, simpleRedis);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/tunnel/id/randomtunnelid`,
            {
                id: 'randomtunnelid', userId: 100, authenticatedTime: new Date().toString(),
                assignedClientIp: '10.0.0.3', trackId: '12',
                clientIp: '192.168.1.100', tun: 'tun0', gatewayId: '1234', serviceNetwork: '192.168.0.0/24'
            })
        await simpleRedis.set(`/tunnel/ip/10.0.0.3`, 'randomtunnelid');
        await simpleRedis.set(`/gateway/1234/tun/tun0`, 'randomtunnelid');

        await tunnel.alive('randomtunnelid');

        let ttl1 = await simpleRedis.ttl('/tunnel/id/randomtunnelid');
        expect(ttl1).to.be.greaterThan(2 * 60 * 1000);

        ttl1 = await simpleRedis.ttl('/tunnel/ip/10.0.0.3');
        expect(ttl1).to.be.greaterThan(2 * 60 * 1000);

        ttl1 = await simpleRedis.ttl('/gateway/1234/tun/tun0');
        expect(ttl1).to.be.greaterThan(2 * 60 * 1000);


    }).timeout(10000)





})
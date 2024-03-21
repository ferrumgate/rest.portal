import chai from 'chai';
import chaiHttp from 'chai-http';
import { Gateway, Network } from '../src/model/network';
import { ConfigService } from '../src/service/configService';
import { DhcpService } from '../src/service/dhcpService';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';

chai.use(chaiHttp);
const expect = chai.expect;

describe('dhcpService', () => {

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
        const dhcp = new DhcpService(configService, simpleRedis);

        const { network, ip } = await dhcp.getEmptyIp(gateway.id);
        expect(network).exist;
        expect(ip).exist;
        const ipstr = Util.bigIntegerToIp(ip);
        expect(ipstr).to.equal('192.168.0.1');

    }).timeout(10000)
    it('getEmptyTrackId will return an trackId', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);

        const dhcp = new DhcpService(configService, simpleRedis);
        for (let i = 1; i < 100; ++i) {
            const { trackId } = await dhcp.getEmptyTrackId();
            expect(trackId).exist;
            expect(trackId).to.equal(i);

            dhcp.lastUsedTrackId = i;
        }

    }).timeout(10000)

    it('getEmptyTrackId will return unique trackId', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);

        const dhcp = new DhcpService(configService, simpleRedis);
        for (let i = 1; i < 100; ++i) {
            const { trackId } = await dhcp.getEmptyTrackId();
            expect(trackId).exist;
            expect(trackId).to.equal(i);
            expect(await simpleRedis.exists('/tunnel/trackId/' + i)).to.be.true;
            dhcp.lastUsedTrackId = i;
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
            const dhcp = new DhcpService(configService2, simpleRedis);
            const ip = await dhcp.getEmptyIp(gateway.id);
        } catch (err) {
            isError = true;
        }
        expect(isError).to.be.true;

    }).timeout(10000)

})
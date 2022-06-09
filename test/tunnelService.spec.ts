
//docker run --net=host --name redis --rm -d redis


import chai from 'chai';
import chaiHttp from 'chai-http';
import { TunnelService } from '../src/service/tunnelService';
import { ConfigService } from '../src/service/configService';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';
import { User } from '../src/model/user';




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
            await tunnel.createTunnel(user, simpleRedis, 'asessionid');
        } catch (err) { isError = true; };
        expect(isError).to.be.true;


    }).timeout(10000)

    it('create tunnel will return with out error', async () => {
        const configService2 = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm');
        await configService2.setConfigPath('/tmp/rest.portal.config2.yaml');
        await configService2.setClientNetwork('192.168.0.0/24')
        const tunnel = new TunnelService(configService2);
        const user: User = { id: 'adfaf' } as User;
        await simpleRedis.hset(`/session/asessionid`, { id: 'asessionid', clientIp: '192.168.1.100' })
        //


        await tunnel.createTunnel(user, simpleRedis, 'asessionid');
        //check every redis data 
        const ipExits = await simpleRedis.sismember(`/clientNetwork/used`, '192.168.0.1');
        expect(ipExits == 1).to.be.true;
        //ip
        expect(Util.bigIntegerToIp(tunnel.lastUsedIp)).to.equal('192.168.0.1');
        //client ip session
        const sessionId = await simpleRedis.get('/client/192.168.0.1', false)
        expect(sessionId).to.equal('asessionid');

        //session
        const session = await simpleRedis.hgetAll(`/session/asessionid`);
        expect(session.id).to.equal('asessionid');
        expect(session.authenticatedTime).exist;
        expect(session.assignedClientIp).to.equal('192.168.0.1');


    }).timeout(10000)





})
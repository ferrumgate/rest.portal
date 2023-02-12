
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
import { SessionService } from '../src/service/sessionService';
import { SummaryService } from '../src/service/summaryService';
import { ESService } from '../src/service/esService';
import { DhcpService } from '../src/service/dhcpService';




chai.use(chaiHttp);
const expect = chai.expect;


describe('summaryService', () => {

    const simpleRedis = new RedisService('localhost:6379,localhost:6390');
    const host = 'https://192.168.88.250:9200';
    const user = 'elastic';
    const pass = '123456';
    beforeEach(async () => {

        await simpleRedis.flushAll();

    })

    it('getConfigSummary', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        configService.config.networks = [];
        configService.config.gateways = [];
        configService.config.users = [];
        configService.config.groups = [];
        configService.config.services = [];
        configService.config.authorizationPolicy.rules = [];
        configService.config.authenticationPolicy.rules = [];


        await configService.saveUser({ id: 'test2' } as any);
        await configService.saveNetwork({ id: 'test4' } as any);
        await configService.saveGateway({ id: 'test4' } as any);
        await configService.saveAuthenticationPolicyRule({ id: 'test5' } as any);
        await configService.saveAuthorizationPolicyRule({ id: 'test6' } as any);
        await configService.saveService({ id: 'test7' } as any);
        await configService.saveGroup({ id: 'test10' } as any);
        const sessionService = new SessionService(configService, simpleRedis);
        const tunnelService = new TunnelService(configService, simpleRedis, new DhcpService(configService, simpleRedis));
        const es = new ESService(configService, host, user, pass);
        const summaryService = new SummaryService(configService, tunnelService, sessionService, simpleRedis, es);
        const sum = await summaryService.getSummaryConfig();
        expect(sum.authnCount).to.equal(1);
        expect(sum.authzCount).to.equal(1);
        expect(sum.gatewayCount).to.equal(1);
        expect(sum.networkCount).to.equal(1);
        expect(sum.serviceCount).to.equal(1);
        expect(sum.userCount).to.equal(1);
        expect(sum.groupCount).to.equal(1);



    }).timeout(10000)


})
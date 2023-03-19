
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { ConfigService } from '../src/service/configService';
import { Util } from '../src/util';
import { AuthenticationRule } from '../src/model/authenticationPolicy';
import { PolicyService } from '../src/service/policyService';
import { TunnelService } from '../src/service/tunnelService';
import { RedisService } from '../src/service/redisService';
import { Network } from '../src/model/network';
import { Gateway } from '../src/model/network';
import { Service } from '../src/model/service';
import { User } from '../src/model/user';
import { AuthorizationRule } from '../src/model/authorizationPolicy';
import { ESService } from '../src/service/esService';
import { Tunnel } from '../src/model/tunnel';
import { AuthSession } from '../src/model/authSession';





chai.use(chaiHttp);
const expect = chai.expect;




describe('policyService ', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const host = 'https://192.168.88.250:9200';
    const user = 'elastic';
    const pass = '123456';
    beforeEach((done) => {

        if (fs.existsSync(filename))
            fs.rmSync(filename);
        done();
    })

    it('isUserIdOrGroupIdAllowed', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }

        const policyService = new PolicyService(configService)
        let result = await policyService.isUserIdOrGroupIdAllowed(rule, { id: 'x', groupIds: [] } as any)
        expect(result).to.be.false;

        let result2 = await policyService.isUserIdOrGroupIdAllowed(rule, { id: 'somegroupid', groupIds: [] } as any)
        expect(result2).to.be.true;

        let result3 = await policyService.isUserIdOrGroupIdAllowed(rule, { id: 'adae', groupIds: ['somegroupid'] } as any)
        expect(result3).to.be.true;

        rule.userOrgroupIds = [];//empty 
        let result4 = await policyService.isUserIdOrGroupIdAllowed(rule, { id: 'adae', groupIds: ['somegroupid'] } as any)
        expect(result4).to.be.true;



    }).timeout(5000);


    it('is2FA', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }

        const policyService = new PolicyService(configService);
        let result = await policyService.is2FA(rule, false)
        expect(result).to.be.true;

        let result2 = await policyService.is2FA(rule, true)
        expect(result2).to.be.true;

        rule.profile.is2FA = true;
        let result3 = await policyService.is2FA(rule, false)
        expect(result3).to.be.false;

        let result4 = await policyService.is2FA(rule, true)
        expect(result4).to.be.true;



    }).timeout(5000);


    it('isCustomWhiteListContains', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {

            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }

        const policyService = new PolicyService(configService);
        let result = await policyService.isCustomWhiteListContains(rule, '1.2.3,4')
        expect(result).to.be.false;

        rule.profile.ips = [{ ip: '192.168.0.1' }]
        let result2 = await policyService.isCustomWhiteListContains(rule, '192.168.0.1')
        expect(result2).to.be.true;

        rule.profile.ips = [{ ip: '192.168.0.1' }, { ip: '192.168.9.10/32' }, { ip: '192.168.10.0/24' }]
        let result3 = await policyService.isCustomWhiteListContains(rule, '192.168.9.10')
        expect(result3).to.be.true;



        let result4 = await policyService.isCustomWhiteListContains(rule, '192.168.10.15')
        expect(result4).to.be.true;

        let result5 = await policyService.isCustomWhiteListContains(rule, '192.168.9.11')
        expect(result5).to.be.false;



    }).timeout(5000);


    it('isIpIntelligenceWhiteListContains', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {

            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }

        const policyService = new PolicyService(configService);
        let result = await policyService.isIpIntelligenceWhiteListContains(rule, '1.2.3,4')
        expect(result).to.be.false;

        rule.profile.ipIntelligence = { isBlackList: false, isCrawler: false, isHosting: false, isProxy: false, isWhiteList: true }
        configService.config.ipIntelligence.whiteList.push({ id: 'adfa', insertDate: '', val: '192.168.0.1/32' })
        let result2 = await policyService.isIpIntelligenceWhiteListContains(rule, '192.168.0.1')
        expect(result2).to.be.true;


        rule.profile.ipIntelligence = { isBlackList: false, isCrawler: false, isHosting: false, isProxy: false, isWhiteList: true }
        configService.config.ipIntelligence.whiteList.push({ id: 'adfa1', insertDate: '', val: '192.168.0.1/32' })
        configService.config.ipIntelligence.whiteList.push({ id: 'adfa2', insertDate: '', val: '192.168.9.10/32' })
        configService.config.ipIntelligence.whiteList.push({ id: 'adfa3', insertDate: '', val: '192.168.10.0/24' })
        let result3 = await policyService.isIpIntelligenceWhiteListContains(rule, '192.168.9.10')
        expect(result3).to.be.true;


        let result4 = await policyService.isIpIntelligenceWhiteListContains(rule, '192.168.10.15')
        expect(result4).to.be.true;

        let result5 = await policyService.isIpIntelligenceWhiteListContains(rule, '192.168.9.11')
        expect(result5).to.be.false;



    }).timeout(5000);


    it('isIpIntelligenceBlackListContains', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {

            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }

        const policyService = new PolicyService(configService);
        let result = await policyService.isIpIntelligenceBlackListContains(rule, '1.2.3,4')
        expect(result).to.be.false;

        rule.profile.ipIntelligence = { isBlackList: true, isCrawler: false, isHosting: false, isProxy: false, isWhiteList: false }
        configService.config.ipIntelligence.blackList.push({ id: 'adfa', insertDate: '', val: '192.168.0.1/32' })
        let result2 = await policyService.isIpIntelligenceBlackListContains(rule, '192.168.0.1')
        expect(result2).to.be.true;


        rule.profile.ipIntelligence = { isBlackList: true, isCrawler: false, isHosting: false, isProxy: false, isWhiteList: false }
        configService.config.ipIntelligence.blackList.push({ id: 'adfa1', insertDate: '', val: '192.168.0.1/32' })
        configService.config.ipIntelligence.blackList.push({ id: 'adfa2', insertDate: '', val: '192.168.9.10/32' })
        configService.config.ipIntelligence.blackList.push({ id: 'adfa3', insertDate: '', val: '192.168.10.0/24' })
        let result3 = await policyService.isIpIntelligenceBlackListContains(rule, '192.168.9.10')
        expect(result3).to.be.true;


        let result4 = await policyService.isIpIntelligenceBlackListContains(rule, '192.168.10.15')
        expect(result4).to.be.true;

        let result5 = await policyService.isIpIntelligenceBlackListContains(rule, '192.168.9.11')
        expect(result5).to.be.false;



    }).timeout(5000);



    it('isIpIntelligenceBlackIp', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {

            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }

        const policyService = new PolicyService(configService);
        let result = await policyService.isIpIntelligenceBlackIp(rule, { isCrawlerIp: true, isHostingIp: false, isProxyIp: false } as AuthSession);
        expect(result).to.be.false;

        rule.profile.ipIntelligence = { isBlackList: false, isWhiteList: false, isCrawler: true, isHosting: false, isProxy: false };
        result = await policyService.isIpIntelligenceBlackIp(rule, { isCrawlerIp: true, isHostingIp: false, isProxyIp: false } as AuthSession);
        expect(result).to.be.true;

        rule.profile.ipIntelligence = { isBlackList: false, isWhiteList: false, isCrawler: false, isHosting: true, isProxy: false };
        result = await policyService.isIpIntelligenceBlackIp(rule, { isCrawlerIp: false, isHostingIp: true, isProxyIp: false } as AuthSession);
        expect(result).to.be.true;


        rule.profile.ipIntelligence = { isBlackList: false, isWhiteList: false, isCrawler: false, isHosting: false, isProxy: true };
        result = await policyService.isIpIntelligenceBlackIp(rule, { isCrawlerIp: false, isHostingIp: false, isProxyIp: true } as AuthSession);
        expect(result).to.be.true;


    }).timeout(5000);

    it('isIpIntelligenceCountryContains', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {

            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }

        const policyService = new PolicyService(configService);
        let result = await policyService.isIpIntelligenceCountryContains(rule);
        expect(result).to.be.true;

        rule.profile.locations = [
            { countryCode: 'TR' }
        ]
        result = await policyService.isIpIntelligenceCountryContains(rule);
        expect(result).to.be.true;

        result = await policyService.isIpIntelligenceCountryContains(rule, 'TR');
        expect(result).to.be.true;

        result = await policyService.isIpIntelligenceCountryContains(rule, 'UK');
        expect(result).to.be.false;



    }).timeout(5000);


    it('isTimeAllowed', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {

            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }

        const policyService = new PolicyService(configService);
        let result = await policyService.isTimeAllowed(rule);
        expect(result).to.be.true;

        const dayOfWeek = new Date().getDay() + 1;
        rule.profile.times = [
            { timezone: 'America/New_York', days: [dayOfWeek < 7 ? dayOfWeek : 0] }
        ]

        result = await policyService.isTimeAllowed(rule);
        expect(result).to.be.false;

        rule.profile.times = [
            { timezone: 'America/New_York', days: [dayOfWeek < 7 ? dayOfWeek : 0], startTime: 0, endTime: 1 }
        ]

        result = await policyService.isTimeAllowed(rule);
        expect(result).to.be.false;

        rule.profile.times = [
            { timezone: 'America/New_York', days: [0, 1, 2, 3, 4, 5, 6] }
        ]

        result = await policyService.isTimeAllowed(rule);
        expect(result).to.be.true;




    }).timeout(5000);


    it('isIpIntelligenceAllowed', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {

            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }

        const policyService = new PolicyService(configService);
        rule.profile.ips = [{ ip: '1.1.1.1/32' }];
        let result = await policyService.isIpIntelligenceAllowed(rule, {} as any, '1.1.1.1');
        expect(result).to.be.true;


        rule.profile.ips = [];
        configService.config.ipIntelligence.whiteList = [{ val: '1.2.3.4/32' } as any]
        rule.profile.ipIntelligence = { isBlackList: false, isWhiteList: true, isCrawler: false, isHosting: false, isProxy: false }
        result = await policyService.isIpIntelligenceAllowed(rule, {} as any, '1.2.3.4');
        expect(result).to.be.true;


        rule.profile.ips = [];
        configService.config.ipIntelligence.whiteList = [];
        configService.config.ipIntelligence.blackList = [{ val: '1.2.3.4/32' } as any]
        rule.profile.ipIntelligence = { isBlackList: true, isWhiteList: false, isCrawler: false, isHosting: false, isProxy: false }
        result = await policyService.isIpIntelligenceAllowed(rule, {} as any, '1.2.3.4');
        expect(result).to.be.false;


        rule.profile.ips = [];
        configService.config.ipIntelligence.whiteList = [];
        configService.config.ipIntelligence.blackList = []
        rule.profile.ipIntelligence = { isBlackList: false, isWhiteList: false, isCrawler: true, isHosting: true, isProxy: true }
        result = await policyService.isIpIntelligenceAllowed(rule, { isProxyIp: true } as any, '1.2.3.4');
        expect(result).to.be.false;


        rule.profile.ips = [];
        configService.config.ipIntelligence.whiteList = [];
        configService.config.ipIntelligence.blackList = []
        rule.profile.ipIntelligence = { isBlackList: false, isWhiteList: false, isCrawler: false, isHosting: false, isProxy: false }
        rule.profile.locations = [{ countryCode: 'TR' }]
        result = await policyService.isIpIntelligenceAllowed(rule, { isProxyIp: true, countryCode: 'TR' } as any, '1.2.3.4');
        expect(result).to.be.true;



        rule.profile.ips = [];
        configService.config.ipIntelligence.whiteList = [];
        configService.config.ipIntelligence.blackList = []
        rule.profile.ipIntelligence = { isBlackList: false, isWhiteList: false, isCrawler: false, isHosting: false, isProxy: false }
        rule.profile.locations = [{ countryCode: 'UK' }]
        result = await policyService.isIpIntelligenceAllowed(rule, { isProxyIp: true, countryCode: 'TR' } as any, '1.2.3.4');
        expect(result).to.be.false;






    }).timeout(5000);



    it('authenticate', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isEnabled: true
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

        configService.config.networks = [net];
        configService.config.gateways = [gateway];

        let redisValue = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', gatewayId: gateway.id };
        await redisService.hset(`/tunnel/id/testsession`, redisValue);

        const policyService = new PolicyService(configService);

        //no tunnel with this key
        try {
            const session: AuthSession = { id: '1', is2FA: true, userId: '1' } as AuthSession;
            let result = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any,
                session, undefined)

        } catch (err) { }
        expect(policyService.errorNumber).to.equal(1);


        // no session

        try {
            const session: AuthSession = { id: '1', is2FA: true } as AuthSession;
            const tun = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', gatewayId: 'non absent gateway' };
            let result = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any,
                session, tun)

        } catch (err) { }
        expect(policyService.errorNumber).to.equal(8);


        //no gateway

        try {
            const tun = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', gatewayId: 'non absent gateway' };
            await redisService.hset(`/tunnel/id/testsession`, tun);
            const session: AuthSession = { id: '1', is2FA: true, userId: '1' } as AuthSession;
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any,
                session, tun)
        } catch (err) { }
        expect(policyService.errorNumber).to.equal(3);


        //no network

        try {
            const newGateway = Util.clone<Gateway>(gateway);
            newGateway.networkId = 'not absent';
            configService.config.gateways = [newGateway];
            const tun = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', gatewayId: newGateway.id };
            const session: AuthSession = { id: '1', is2FA: true, userId: '1' } as AuthSession;
            await redisService.hset(`/tunnel/id/testsession`, tun);
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any,
                session, tun)
        } catch (err) { }
        expect(policyService.errorNumber).to.equal(5);

        configService.config.gateways = [gateway];

        //rule drop
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: net.id,
            userOrgroupIds: ['somegroupid'],
            profile: {
                is2FA: true,
                ips: [{ ip: '10.0.0.0/24' }]
            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()
        }



        configService.config.authenticationPolicy.rules = [rule];

        try {

            configService.config.gateways = [gateway];
            const tun = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', gatewayId: gateway.id };
            await redisService.hset(`/tunnel/id/testsession`, tun);
            const session: AuthSession = { id: '1', is2FA: true, userId: '1', ip: '10.0.0.2' } as AuthSession;
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any, session, tun)
        } catch (err) { }
        expect(policyService.errorNumber).to.equal(0);


        //
        try {

            configService.config.gateways = [gateway];
            rule.profile.ips = [];
            configService.config.ipIntelligence.blackList = [{ val: '0.0.0.0/0', id: '12', insertDate: '' }];
            rule.profile.ipIntelligence = { isBlackList: true, isCrawler: false, isHosting: false, isProxy: false, isWhiteList: false };
            const tun = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', gatewayId: gateway.id };
            await redisService.hset(`/tunnel/id/testsession`, tun);
            const session: AuthSession = { id: '1', is2FA: true, userId: '1', ip: '10.0.0.2' } as AuthSession;
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any, session, tun)
        } catch (err) { }
        expect(policyService.errorNumber).to.equal(100);












    }).timeout(5000);


    const esHost = 'https://192.168.88.250:9200';
    const esUser = "elastic";
    const esPass = '123456';
    it('authorize', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isEnabled: true
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

        const service: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],
            host: '1.2.3.4',
            networkId: net.id,
            tcp: 3306, assignedIp: '1.3',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        configService.config.services = [service];
        configService.config.networks = [net];
        configService.config.gateways = [gateway];

        let redisValue = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', trackId: 3, gatewayId: gateway.id, is2FA: true };
        await redisService.hset(`/tunnel/id/testsession`, redisValue);
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession');
        await redisService.set(`/tunnel/trackId/3`, 'testsession');

        const es = new ESService(configService, esHost, esUser, esPass);

        const policyService = new PolicyService(configService);

        //no client with this key
        try {

            let result = await policyService.authorize(null as any, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(1);

        //no tunnel with this key
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession2');
        await redisService.set(`/tunnel/trackId/3`, 'testsession2');
        try {
            let result = await policyService.authorize({}, service.id)

        } catch (err) {
            console.log(err);
        }
        expect(policyService.authorizeErrorNumber).to.equal(2);


        //no user
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession');
        await redisService.set(`/tunnel/trackId/3`, 'testsession');
        try {
            let result = await policyService.authorize(redisValue, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(3);


        const user1: User = {
            username: 'hamza@ferrumgate.com',
            id: 'someid',
            name: 'hamza',
            source: 'local',
            roleIds: ['Admin'],
            isLocked: false, isVerified: true,
            password: Util.bcryptHash('somepass'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            groupIds: ['ad']

        }
        configService.config.users = [user1];

        //no service
        let redisValue2 = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', trackId: 3, gatewayId: gateway.id, is2FA: true, userId: user1.id };
        await redisService.hset(`/tunnel/id/testsession`, redisValue2);
        configService.config.services = [];
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession');
        await redisService.set(`/tunnel/trackId/3`, 'testsession');
        try {
            let result = await policyService.authorize(redisValue2, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(5);
        configService.config.services = [service];
        //service disabled
        service.isEnabled = false;
        configService.config.services = [service];
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession');
        await redisService.set(`/tunnel/trackId/3`, 'testsession');
        try {
            let result = await policyService.authorize(redisValue2, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(6);
        service.isEnabled = true;

        //no network
        configService.config.networks = [];
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession');
        await redisService.set(`/tunnel/trackId/3`, 'testsession');
        try {
            let result = await policyService.authorize(redisValue2, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(7);
        configService.config.networks = [net];


        //rule 
        let rule: AuthorizationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: net.id,
            serviceId: service.id,
            userOrgroupIds: [user1.id],

            profile: {
                is2FA: true,
            },
            isEnabled: false,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        configService.config.authorizationPolicy.rules = [rule];

        try {
            let result = await policyService.authorize(redisValue2, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(100);

        rule.isEnabled = true;


        try {
            let result = await policyService.authorize(redisValue2, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(0); //success

    }).timeout(5000);


    it('userNetworks', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isEnabled: true
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

        const net2: Network = {
            id: '12323ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isEnabled: true
        }

        configService.config.networks = [net, net2];
        configService.config.gateways = [gateway];

        //rule drop
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: net.id,
            userOrgroupIds: ['somegroupid'],
            profile: {
                is2FA: true,
                ips: []
            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }
        configService.config.authenticationPolicy.rules = [rule];

        const session: AuthSession = { is2FA: true, ip: '1.1.1.1' } as AuthSession;
        const tunnel: Tunnel = { clientIp: '1.1.1.1' };

        const policyService = new PolicyService(configService);
        //prepare for test
        net.isEnabled = false; net2.isEnabled = false;
        let result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(0);

        //prepare for test
        net.isEnabled = true, net2.isEnabled = true;
        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].action).to.be.equal('allow');



        configService.config.gateways = [];
        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].needsGateway).to.be.true;

        session.is2FA = false;
        //push it back
        configService.config.gateways = [gateway];
        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].needs2FA).to.be.true;
        expect(result[0].needsIp).to.be.false;
        expect(result[0].needsTime).to.be.false;


        rule.profile.ips?.push({ ip: '1.2.3.4' });
        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].needs2FA).to.be.true;
        expect(result[0].needsIp).to.be.false;
        expect(result[0].needsTime).to.be.false;

        // 2fa is true, all ips are in blacklist
        session.is2FA = true;
        rule.profile.ipIntelligence = { isBlackList: true, isCrawler: true, isHosting: true, isProxy: true, isWhiteList: true };
        configService.config.ipIntelligence.blackList.push({ id: '123', insertDate: '', val: '0.0.0.0/0' });
        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].needs2FA).to.be.false;
        expect(result[0].needsIp).to.be.true;
        expect(result[0].needsTime).to.be.false;

        // 2fa is true, all ips are in blacklist, only 1.1.1.1 is in whitelist
        session.is2FA = true;
        rule.profile.ipIntelligence = { isBlackList: true, isCrawler: true, isHosting: true, isProxy: true, isWhiteList: true };
        configService.config.ipIntelligence.blackList.push({ id: '123', insertDate: '', val: '0.0.0.0/0' });
        configService.config.ipIntelligence.whiteList.push({ id: '123', insertDate: '', val: session.ip + '/32' });
        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].action).to.be.equal('allow');



        // 2fa is true, all ips are in blacklist, only 1.1.1.1 is in whitelist but time problem 
        session.is2FA = true;
        rule.profile.ipIntelligence = { isBlackList: true, isCrawler: true, isHosting: true, isProxy: true, isWhiteList: true };
        configService.config.ipIntelligence.blackList.push({ id: '123', insertDate: '', val: '0.0.0.0/0' });
        configService.config.ipIntelligence.whiteList.push({ id: '123', insertDate: '', val: session.ip + '/32' });
        const dayOfWeek = new Date().getDay() + 1;
        rule.profile.times = [
            { timezone: 'America/New_York', days: [dayOfWeek < 7 ? dayOfWeek : 0] }
        ]
        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].needs2FA).to.be.false;
        expect(result[0].needsIp).to.be.false;
        expect(result[0].needsTime).to.be.true;






    })




})



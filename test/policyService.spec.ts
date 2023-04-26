
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
import { IpIntelligenceListService } from '../src/service/ipIntelligenceService';
import { IpIntelligenceService } from '../src/service/ipIntelligenceService';
import { InputService } from '../src/service/inputService';
import { config } from 'process';
import { IpIntelligenceList } from '../src/model/IpIntelligence';






chai.use(chaiHttp);
const expect = chai.expect;



describe('policyService ', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const host = 'https://192.168.88.250:9200';
    const user = 'elastic';
    const pass = '123456';

    beforeEach(async () => {

        if (fs.existsSync(filename))
            fs.rmSync(filename);

    })


    it('isUserIdOrGroupIdAllowed', async () => {
        const redisService = new RedisService();

        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel)
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
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel);
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
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel);
        let result = await policyService.isCustomWhiteListContains(rule, '1.2.3,4')
        expect(result).to.be.false;

        rule.profile.whiteListIps = [{ ip: '192.168.0.1' }]
        let result2 = await policyService.isCustomWhiteListContains(rule, '192.168.0.1')
        expect(result2).to.be.true;

        rule.profile.whiteListIps = [{ ip: '192.168.0.1' }, { ip: '192.168.9.10/32' }, { ip: '192.168.10.0/24' }]
        let result3 = await policyService.isCustomWhiteListContains(rule, '192.168.9.10')
        expect(result3).to.be.true;



        let result4 = await policyService.isCustomWhiteListContains(rule, '192.168.10.15')
        expect(result4).to.be.true;

        let result5 = await policyService.isCustomWhiteListContains(rule, '192.168.9.11')
        expect(result5).to.be.false;



    }).timeout(5000);


    it('isCustomBlackListContains', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel);
        let result = await policyService.isCustomBlackListContains(rule, '1.2.3,4')
        expect(result).to.be.false;

        rule.profile.blackListIps = [{ ip: '192.168.0.1' }]
        let result2 = await policyService.isCustomBlackListContains(rule, '192.168.0.1')
        expect(result2).to.be.true;

        rule.profile.blackListIps = [{ ip: '192.168.0.1' }, { ip: '192.168.9.10/32' }, { ip: '192.168.10.0/24' }]
        let result3 = await policyService.isCustomBlackListContains(rule, '192.168.9.10')
        expect(result3).to.be.true;



        let result4 = await policyService.isCustomBlackListContains(rule, '192.168.10.15')
        expect(result4).to.be.true;

        let result5 = await policyService.isCustomBlackListContains(rule, '192.168.9.11')
        expect(result5).to.be.false;



    }).timeout(5000);

    function writeToTmpFile(content: string) {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, content);
        return tmpFolderFile;
    }

    it('isIpIntelligenceWhiteListContains', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel);
        let result = await policyService.isIpIntelligenceWhiteListContains(rule, '1.2.3,4')
        expect(result).to.be.false;

        const list: IpIntelligenceList = {
            id: Util.randomNumberString(),
            name: 'test', insertDate: new Date().toISOString(), updateDate: new Date().toISOString(),

        }
        await configService.saveIpIntelligenceList(list);
        let tmpFile = writeToTmpFile("192.168.0.1/32")
        await ipintel.listService.saveToStore(list, tmpFile, 0);
        await Util.sleep(1000);

        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [], whiteLists: [list.id] };
        let result2 = await policyService.isIpIntelligenceWhiteListContains(rule, '192.168.0.1')
        expect(result2).to.be.true;


        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [], whiteLists: [list.id] };
        tmpFile = writeToTmpFile("192.168.0.1/32\n192.168.9.10/32\n192.168.10.0/24")
        await ipintel.listService.deleteFromStore(list, 0);
        await ipintel.listService.saveToStore(list, tmpFile, 0);
        await Util.sleep(1000);
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
        const inputService = new InputService()
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel);
        let result = await policyService.isIpIntelligenceBlackListContains(rule, '1.2.3,4')
        expect(result).to.be.false;

        const list: IpIntelligenceList = {
            id: Util.randomNumberString(),
            name: 'test', insertDate: new Date().toISOString(), updateDate: new Date().toISOString(),
        }

        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [list.id], whiteLists: [] };

        //save

        await configService.saveIpIntelligenceList(list);
        let tmpFile = writeToTmpFile("192.168.0.1/32")
        await ipintel.listService.saveToStore(list, tmpFile, 0);
        await Util.sleep(1000);


        let result2 = await policyService.isIpIntelligenceBlackListContains(rule, '192.168.0.1')
        expect(result2).to.be.true;


        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [list.id], whiteLists: [] };

        tmpFile = writeToTmpFile("192.168.0.1/32\n192.168.9.10/32\n192.168.10.0/24")
        await ipintel.listService.saveToStore(list, tmpFile, 0);
        await Util.sleep(1000);

        let result3 = await policyService.isIpIntelligenceBlackListContains(rule, '192.168.9.10')
        expect(result3).to.be.true;


        let result4 = await policyService.isIpIntelligenceBlackListContains(rule, '192.168.10.15')
        expect(result4).to.be.true;

        let result5 = await policyService.isIpIntelligenceBlackListContains(rule, '192.168.9.11')
        expect(result5).to.be.false;

        //list is not in blacklist
        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: ['someother'], whiteLists: [] };

        let result6 = await policyService.isIpIntelligenceBlackListContains(rule, '192.168.9.10')
        expect(result6).to.be.false;



    }).timeout(5000);



    it('isIpIntelligenceBlackIp', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel);
        let result = await policyService.isIpIntelligenceBlackIp(rule, { isCrawlerIp: true, isHostingIp: false, isProxyIp: false } as AuthSession);
        expect(result).to.be.false;

        rule.profile.ipIntelligence = { isCrawler: true, isHosting: false, isProxy: false, blackLists: [], whiteLists: [] };
        result = await policyService.isIpIntelligenceBlackIp(rule, { isCrawlerIp: true, isHostingIp: false, isProxyIp: false } as AuthSession);
        expect(result).to.be.true;

        rule.profile.ipIntelligence = { isCrawler: false, isHosting: true, isProxy: false, blackLists: [], whiteLists: [] };
        result = await policyService.isIpIntelligenceBlackIp(rule, { isCrawlerIp: false, isHostingIp: true, isProxyIp: false } as AuthSession);
        expect(result).to.be.true;


        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: true, blackLists: [], whiteLists: [] };
        result = await policyService.isIpIntelligenceBlackIp(rule, { isCrawlerIp: false, isHostingIp: false, isProxyIp: true } as AuthSession);
        expect(result).to.be.true;


    }).timeout(5000);



    it('isIpIntelligenceCountryContains', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel);
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
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel);
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

    async function saveIpList(configService: ConfigService, ipintel: IpIntelligenceService, content: string) {
        const list: IpIntelligenceList = {
            id: Util.randomNumberString(),
            name: 'test', insertDate: new Date().toISOString(), updateDate: new Date().toISOString(),

        }
        await configService.saveIpIntelligenceList(list);
        let tmpFile = writeToTmpFile(content);
        await ipintel.listService.saveToStore(list, tmpFile, 0);
        await Util.sleep(1000);
        return list;
    }

    it('isIpIntelligenceAllowed', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService()
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel);
        rule.profile.whiteListIps = [{ ip: '1.1.1.1/32' }];
        rule.profile.blackListIps = [];
        let result = await policyService.isIpIntelligenceAllowed(rule, {} as any, '1.1.1.1');
        expect(result).to.be.true;


        rule.profile.blackListIps = [{ ip: '1.1.1.1/32' }];
        rule.profile.whiteListIps = [];
        result = await policyService.isIpIntelligenceAllowed(rule, {} as any, '1.1.1.1');
        expect(result).to.be.false;


        rule.profile.whiteListIps = [];
        rule.profile.blackListIps = [];
        const list1 = await saveIpList(configService, ipintel, '1.2.3.4/32');
        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [], whiteLists: [list1.id] };
        result = await policyService.isIpIntelligenceAllowed(rule, {} as any, '1.2.3.4');
        expect(result).to.be.true;
        await esService.reset();


        rule.profile.whiteListIps = [];
        rule.profile.blackListIps = [];
        const list2 = await saveIpList(configService, ipintel, '1.2.3.4/32');
        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [list2.id], whiteLists: [] };
        result = await policyService.isIpIntelligenceAllowed(rule, {} as any, '1.2.3.4');
        expect(result).to.be.false;
        await esService.reset();


        rule.profile.whiteListIps = [];
        rule.profile.blackListIps = [];
        rule.profile.ipIntelligence = { isCrawler: true, isHosting: true, isProxy: true, blackLists: [], whiteLists: [] };
        result = await policyService.isIpIntelligenceAllowed(rule, { isProxyIp: true } as any, '1.2.3.4');
        expect(result).to.be.false;


        rule.profile.whiteListIps = [];
        rule.profile.blackListIps = [];
        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [], whiteLists: [] };
        rule.profile.locations = [{ countryCode: 'TR' }]
        result = await policyService.isIpIntelligenceAllowed(rule, { isProxyIp: true, countryCode: 'TR' } as any, '1.2.3.4');
        expect(result).to.be.true;



        rule.profile.whiteListIps = [];
        rule.profile.blackListIps = [];
        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [], whiteLists: [] };
        rule.profile.locations = [{ countryCode: 'UK' }]
        result = await policyService.isIpIntelligenceAllowed(rule, { isProxyIp: true, countryCode: 'TR' } as any, '1.2.3.4');
        expect(result).to.be.false;



    }).timeout(5000);



    it('authenticate', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();
        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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

        const policyService = new PolicyService(configService, ipintel);

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
                whiteListIps: [{ ip: '10.0.0.0/24' }]
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
            rule.profile.whiteListIps = [];
            const list = await saveIpList(configService, ipintel, '0.0.0.0/0');
            rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [list.id], whiteLists: [] };
            const tun = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', gatewayId: gateway.id };
            await redisService.hset(`/tunnel/id/testsession`, tun);
            const session: AuthSession = { id: '1', is2FA: true, userId: '1', ip: '10.0.0.2' } as AuthSession;
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any, session, tun)
        } catch (err) { }
        expect(policyService.errorNumber).to.equal(100);



    }).timeout(5000);



    it('authorize', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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



        const policyService = new PolicyService(configService, ipintel);

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
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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
                whiteListIps: []
            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()


        }
        configService.config.authenticationPolicy.rules = [rule];

        const session: AuthSession = { is2FA: true, ip: '1.1.1.1' } as AuthSession;
        const tunnel: Tunnel = { clientIp: '1.1.1.1' };

        const policyService = new PolicyService(configService, ipintel);
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


        rule.profile.whiteListIps?.push({ ip: '1.2.3.4' });
        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].needs2FA).to.be.true;
        expect(result[0].needsIp).to.be.false;
        expect(result[0].needsTime).to.be.false;

        // 2fa is true, all ips are in blacklist
        session.is2FA = true;
        const list1 = await saveIpList(configService, ipintel, '0.0.0.0/0');
        rule.profile.ipIntelligence = { isCrawler: true, isHosting: true, isProxy: true, blackLists: [list1.id], whiteLists: [] };

        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].needs2FA).to.be.false;
        expect(result[0].needsIp).to.be.true;
        expect(result[0].needsTime).to.be.false;

        // 2fa is true, all ips are in blacklist, only 1.1.1.1 is in whitelist
        session.is2FA = true;
        const list2 = await saveIpList(configService, ipintel, session.ip + '/32');
        rule.profile.ipIntelligence = { isCrawler: true, isHosting: true, isProxy: true, blackLists: [list1.id], whiteLists: [list2.id] };
        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].action).to.be.equal('allow');



        // 2fa is true, all ips are in blacklist, only 1.1.1.1 is in whitelist but time problem 
        session.is2FA = true;
        rule.profile.ipIntelligence = { isCrawler: true, isHosting: true, isProxy: true, blackLists: [list1.id], whiteLists: [list2.id] };

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





    it('userDevicePostureParameters', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');
        await esService.reset();

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
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
        configService.config.devicePostures = [
            {
                id: '11231313', insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString(),
                isEnabled: true, labels: [], name: 'windows 10', os: 'win32',
                filePathList: [{ path: 'c:\\test' }],
                registryList: [{ path: 'test2', key: 'test' }],
                processList: [{ path: 'aboo' }]

            },
            {
                id: '11231344', insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString(),
                isEnabled: true, labels: [], name: 'windows 10', os: 'win32',
                filePathList: [{ path: 'c:\\test2' }],
                registryList: [{ path: 'test2', key: 'test2' }],
                processList: [{ path: 'aboo' }]

            }
        ]

        //rule drop
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: net.id,
            userOrgroupIds: ['somegroupid'],
            profile: {
                is2FA: true,
                whiteListIps: [],
                device: { postures: ['11231313', '11231344'] }
            },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),



        }
        configService.config.authenticationPolicy.rules = [rule];

        const session: AuthSession = { is2FA: true, ip: '1.1.1.1' } as AuthSession;
        const tunnel: Tunnel = { clientIp: '1.1.1.1' };

        const policyService = new PolicyService(configService, ipintel);
        //prepare for test
        net.isEnabled = false;
        net2.isEnabled = false;
        let result = await policyService.userDevicePostureParameters({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(0);

        //prepare for test
        net.isEnabled = true;
        net2.isEnabled = true;
        result = await policyService.userDevicePostureParameters({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(5);







    })




})

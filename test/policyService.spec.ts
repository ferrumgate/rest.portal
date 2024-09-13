import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AuthSession } from '../src/model/authSession';
import { AuthenticationRule } from '../src/model/authenticationPolicy';
import { DevicePosture } from '../src/model/authenticationProfile';
import { AuthorizationRule } from '../src/model/authorizationPolicy';
import { IpIntelligenceList } from '../src/model/ipIntelligence';
import { Gateway, Network } from '../src/model/network';
import { Service } from '../src/model/service';
import { Tunnel } from '../src/model/tunnel';
import { User } from '../src/model/user';
import { ErrorCodesInternal } from '../src/restfullException';
import { ConfigService } from '../src/service/configService';
import { ESService } from '../src/service/esService';
import { InputService } from '../src/service/inputService';
import { IpIntelligenceService } from '../src/service/ipIntelligenceService';
import { PolicyAuthnErrors, PolicyService } from '../src/service/policyService';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';
import { esHost, esPass, esUser } from './common.spec';

chai.use(chaiHttp);
const expect = chai.expect;

describe('policyService ', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const host = esHost;
    const user = esUser;
    const pass = esPass;

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
        expect(result.result).to.be.true;

        rule.profile.blackListIps = [{ ip: '1.1.1.1/32' }];
        rule.profile.whiteListIps = [];
        result = await policyService.isIpIntelligenceAllowed(rule, {} as any, '1.1.1.1');
        expect(result.result).to.be.false;
        expect(result.error).to.equal(ErrorCodesInternal.ErrIpIntelligenceCustomBlackListContains);
        expect(result.errorNumber).to.equal(PolicyAuthnErrors.IpIntelligenceCustomBlackListContains);

        rule.profile.whiteListIps = [];
        rule.profile.blackListIps = [];
        const list1 = await saveIpList(configService, ipintel, '1.2.3.4/32');
        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [], whiteLists: [list1.id] };
        result = await policyService.isIpIntelligenceAllowed(rule, {} as any, '1.2.3.4');
        expect(result.result).to.be.true;
        await esService.reset();

        rule.profile.whiteListIps = [];
        rule.profile.blackListIps = [];
        const list2 = await saveIpList(configService, ipintel, '1.2.3.4/32');
        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [list2.id], whiteLists: [] };
        result = await policyService.isIpIntelligenceAllowed(rule, {} as any, '1.2.3.4');
        expect(result.result).to.be.false;
        expect(result.error).to.equal(ErrorCodesInternal.ErrIpIntelligenceBlackListContains);
        expect(result.errorNumber).to.equal(PolicyAuthnErrors.IpIntelligenceBlackListContains);
        await esService.reset();

        rule.profile.whiteListIps = [];
        rule.profile.blackListIps = [];
        rule.profile.ipIntelligence = { isCrawler: true, isHosting: true, isProxy: true, blackLists: [], whiteLists: [] };
        result = await policyService.isIpIntelligenceAllowed(rule, { isProxyIp: true } as any, '1.2.3.4');
        expect(result.result).to.be.false;
        expect(result.error).to.equal(ErrorCodesInternal.ErrIpIntelligenceBlackIp);
        expect(result.errorNumber).to.equal(PolicyAuthnErrors.IpIntelligenceBlackIp);

        rule.profile.whiteListIps = [];
        rule.profile.blackListIps = [];
        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [], whiteLists: [] };
        rule.profile.locations = [{ countryCode: 'TR' }]
        result = await policyService.isIpIntelligenceAllowed(rule, { isProxyIp: true, countryCode: 'TR' } as any, '1.2.3.4');
        expect(result.result).to.be.true;

        rule.profile.whiteListIps = [];
        rule.profile.blackListIps = [];
        rule.profile.ipIntelligence = { isCrawler: false, isHosting: false, isProxy: false, blackLists: [], whiteLists: [] };
        rule.profile.locations = [{ countryCode: 'UK' }]
        result = await policyService.isIpIntelligenceAllowed(rule, { isProxyIp: true, countryCode: 'TR' } as any, '1.2.3.4');
        expect(result.result).to.be.false;

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
                session, undefined, undefined)

        } catch (err) { }
        expect(policyService.errorNumber).to.equal(1);

        // no session

        try {
            const session: AuthSession = { id: '1', is2FA: true } as AuthSession;
            const tun = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', gatewayId: 'non absent gateway' };
            let result = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any,
                session, tun, undefined)

        } catch (err) { }
        expect(policyService.errorNumber).to.equal(8);

        //no gateway

        try {
            const tun = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', gatewayId: 'non absent gateway' };
            await redisService.hset(`/tunnel/id/testsession`, tun);
            const session: AuthSession = { id: '1', is2FA: true, userId: '1' } as AuthSession;
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any,
                session, tun, undefined)
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
                session, tun, undefined)
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
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any, session, tun, undefined)
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
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any, session, tun, undefined)

        } catch (err) {
        }
        expect(policyService.errorNumber).to.equal(11);

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
            hosts: [{ host: '1.2.3.4' }],
            networkId: net.id,
            ports: [{ port: 3306, isTcp: true }],
            assignedIp: '1.3',
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
        expect(result[0].needsDevicePosture).to.be.false;

        // 2fa is true, all ips are in blacklist, only 1.1.1.1 is in whitelist but time is ok, device posture problem 
        session.is2FA = true;
        rule.profile.ipIntelligence = { isCrawler: true, isHosting: true, isProxy: true, blackLists: [list1.id], whiteLists: [list2.id] };

        rule.profile.times = [];
        let posture1: DevicePosture = {
            id: 'posture1',
            name: 'norhtinged',
            isEnabled: true,
            labels: [],
            os: 'win32',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),

        }
        configService.saveDevicePosture(posture1);
        rule.profile.device = { postures: ['posture1'] }
        result = await policyService.userNetworks({ id: 'someid', groupIds: ['somegroupid'] } as any, session, session.ip);
        expect(result.length).to.be.equal(1);
        expect(result[0].needs2FA).to.be.false;
        expect(result[0].needsIp).to.be.false;
        expect(result[0].needsTime).to.be.false;
        expect(result[0].needsDevicePosture).to.be.true;

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

    it('isDevicePostureOsVersionAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(await policy.isDevicePostureOsVersionAllowed({} as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureOsVersionAllowed({ os: { version: '1.2.3' } } as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureOsVersionAllowed({ os: { version: '1.2.3' } } as any, { osVersions: [] } as any)).to.be.true
        expect(await policy.isDevicePostureOsVersionAllowed({ os: { version: '1.2.3' } } as any, { osVersions: [{ release: '1.2.3', name: 'darwin' }] } as any)).to.be.true
        expect(await policy.isDevicePostureOsVersionAllowed({ os: { version: '1.2.3' } } as any, { osVersions: [{ release: '2.2.3', name: 'darwin' }] } as any)).to.be.false
        expect(await policy.isDevicePostureOsVersionAllowed({ os: { version: '09.2.113' } } as any, { osVersions: [{ release: '2.20.3', name: 'darwin' }] } as any)).to.be.false
        expect(await policy.isDevicePostureOsVersionAllowed({ os: { version: '1.2.3' } } as any, { osVersions: [{ release: '1.2.4', name: 'darwin' }] } as any)).to.be.false;
        expect(await policy.isDevicePostureOsVersionAllowed({ os: { version: '1.2.3' } } as any, { osVersions: [{ release: '1.2.4', name: 'darwin' }, { release: '1.2.3', name: 'darwin' }] } as any)).to.be.true;


    })


    it('isDevicePostureClientVersionAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(await policy.isDevicePostureClientVersionAllowed({} as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureClientVersionAllowed({ clientVersion: '1.2.0' } as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureClientVersionAllowed({ clientVersion: '1.2.0' } as any, { clientVersions: [] } as any)).to.be.true
        expect(await policy.isDevicePostureClientVersionAllowed({ clientVersion: '' } as any, { clientVersions: [{ version: '12.2' }] } as any)).to.be.false

        expect(await policy.isDevicePostureClientVersionAllowed({ clientVersion: '1.2.0' } as any, { clientVersions: [{ version: '1.2.0' }] } as any)).to.be.true
        expect(await policy.isDevicePostureClientVersionAllowed({ clientVersion: '1.2.0' } as any, { clientVersions: [{ version: '1.2.1' }] } as any)).to.be.false
        expect(await policy.isDevicePostureClientVersionAllowed({ clientVersion: '1.2.15' } as any, { clientVersions: [{ version: '1.2.2' }] } as any)).to.be.true
        expect(await policy.isDevicePostureClientVersionAllowed({ clientVersion: '1.2.5' } as any, { clientVersions: [{ version: '1.2.2' }] } as any)).to.be.true
        expect(await policy.isDevicePostureClientVersionAllowed({ clientVersion: '1.2.05' } as any, { clientVersions: [{ version: '1.2.2' }] } as any)).to.be.false

    })

    it('isDevicePostureFirewallAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(await policy.isDevicePostureFirewallAllowed({} as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureFirewallAllowed({} as any, { firewallList: [{}] } as any)).to.be.false
        expect(await policy.isDevicePostureFirewallAllowed({ platform: 'linux' } as any, { firewallList: [{}] } as any)).to.be.true;
        expect(await policy.isDevicePostureFirewallAllowed({ platform: 'win32', firewalls: [{}] } as any, { firewallList: [{}] } as any)).to.be.false;
        expect(await policy.isDevicePostureFirewallAllowed({ platform: 'win32', firewalls: [{ isEnabled: true }] } as any, { firewallList: [{}] } as any)).to.be.true;

    })

    it('isDevicePostureAntivirusAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(await policy.isDevicePostureAntivirusAllowed({} as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureAntivirusAllowed({} as any, { antivirusList: [{}] } as any)).to.be.false
        expect(await policy.isDevicePostureAntivirusAllowed({ platform: 'linux' } as any, { antivirusList: [{}] } as any)).to.be.true;
        expect(await policy.isDevicePostureAntivirusAllowed({ platform: 'win32', antiviruses: [{}] } as any, { antivirusList: [{}] } as any)).to.be.false;
        expect(await policy.isDevicePostureAntivirusAllowed({ platform: 'win32', antiviruses: [{ isEnabled: true }] } as any, { antivirusList: [{}] } as any)).to.be.true;

    })

    it('isDevicePostureDiscEncrytpedAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(await policy.isDevicePostureDiscEncryptedAllowed({} as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureDiscEncryptedAllowed({} as any, { discEncryption: true } as any)).to.be.false

        expect(await policy.isDevicePostureDiscEncryptedAllowed({ platform: 'win32', encryptedDiscs: [{}] } as any, { discEncryption: true } as any)).to.be.false;
        expect(await policy.isDevicePostureDiscEncryptedAllowed({ platform: 'win32', encryptedDiscs: [{ isEncrypted: true }] } as any, { discEncryption: true } as any)).to.be.true;

    })

    it('isDevicePostureMacAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(await policy.isDevicePostureMacAllowed({} as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureMacAllowed({} as any, { macList: [{}] } as any)).to.be.false

        expect(await policy.isDevicePostureMacAllowed({ platform: 'win32', macs: ['123'] } as any, { macList: [{ value: '123' }, { value: '1234' }] } as any)).to.be.true;
        expect(await policy.isDevicePostureMacAllowed({ platform: 'win32', macs: ['12345', '1234'] } as any, { macList: [{ value: '123' }, { value: '1234' }] } as any)).to.be.true;
        expect(await policy.isDevicePostureMacAllowed({ platform: 'win32', macs: ['12345'] } as any, { macList: [{ value: '123' }, { value: '1234' }] } as any)).to.be.false;

    })

    it('isDevicePostureSerialAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(await policy.isDevicePostureSerialAllowed({} as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureSerialAllowed({} as any, { serialList: [{}] } as any)).to.be.false

        expect(await policy.isDevicePostureSerialAllowed({ platform: 'win32', serial: { value: '123' } } as any, { serialList: [{ value: '123' }, { value: '1234' }] } as any)).to.be.true;
        expect(await policy.isDevicePostureSerialAllowed({ platform: 'win32', serial: { value: '123' } } as any, { serialList: [{ value: '123' }, { value: '1234' }] } as any)).to.be.true;

        expect(await policy.isDevicePostureSerialAllowed({ platform: 'win32', serial: { value: '12345' } } as any, { serialList: [{ value: '123' }, { value: '1234' }] } as any)).to.be.false;

    })

    it('isDevicePostureSerialAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(await policy.isDevicePostureFileAllowed({} as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureFileAllowed({} as any, { filePathList: [{}] } as any)).to.be.false

        expect(await policy.isDevicePostureFileAllowed({ files: [{ path: 'test' }] } as any, { filePathList: [{ path: 'test' }] } as any)).to.be.true
        expect(await policy.isDevicePostureFileAllowed({ files: [{ path: 'test' }] } as any, { filePathList: [{ path: 'test', sha256: 'a' }] } as any)).to.be.false
        expect(await policy.isDevicePostureFileAllowed({ files: [{ path: 'test', sha256: 'a' }] } as any, { filePathList: [{ path: 'test', sha256: 'a' }] } as any)).to.be.true
        expect(await policy.isDevicePostureFileAllowed({ files: [{ path: 'test', sha256: 'a' }] } as any, { filePathList: [{ path: 'test', sha256: 'a' }, { path: 'b' }] } as any)).to.be.false

    })

    it('isDevicePostureProcessAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(await policy.isDevicePostureProcessAllowed({} as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureProcessAllowed({} as any, { processList: [{}] } as any)).to.be.false

        expect(await policy.isDevicePostureProcessAllowed({ processes: [{ path: 'test' }] } as any, { processList: [{ path: 'test' }] } as any)).to.be.true
        expect(await policy.isDevicePostureProcessAllowed({ processes: [{ path: 'test' }] } as any, { processList: [{ path: 'test', sha256: 'a' }] } as any)).to.be.false
        expect(await policy.isDevicePostureProcessAllowed({ processes: [{ path: 'test', sha256: 'a' }] } as any, { processList: [{ path: 'test', }] } as any)).to.be.true
        expect(await policy.isDevicePostureProcessAllowed({ processes: [{ path: 'test', sha256: 'a' }] } as any, { processList: [{ path: 'test', sha256: 'a' }, { path: 'b' }] } as any)).to.be.false

    })

    it('isDevicePostureRegistryAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(await policy.isDevicePostureRegistryAllowed({} as any, {} as any)).to.be.true
        expect(await policy.isDevicePostureRegistryAllowed({ platform: 'linux' } as any, { registryList: [{}] } as any)).to.be.true;

        expect(await policy.isDevicePostureRegistryAllowed({ platform: 'win32', registries: [{ path: 'test' }] } as any, { registryList: [{ path: 'test' }] } as any)).to.be.true
        expect(await policy.isDevicePostureRegistryAllowed({ platform: 'win32', registries: [{ path: 'test' }] } as any, { registryList: [{ path: 'test', key: 'a' }] } as any)).to.be.false
        expect(await policy.isDevicePostureRegistryAllowed({ platform: 'win32', registries: [{ path: 'test', key: 'a' }] } as any, { registryList: [{ path: 'test', key: 'a' }] } as any)).to.be.true
        expect(await policy.isDevicePostureRegistryAllowed({ platform: 'win32', registries: [{ path: 'test', key: 'a' }] } as any, { registryList: [{ path: 'test', key: 'a' }, { path: 'b' }] } as any)).to.be.false

    })

    it('isDevicePostureAllowed', async () => {

        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const inputService = new InputService();
        const esService = new ESService(configService, host, user, pass, '1s');

        const ipintel = new IpIntelligenceService(configService, redisService, inputService, esService);
        await configService.setES({ host: host, user: user, pass: pass })
        configService.config.authenticationPolicy.rules = [];

        const policy = new PolicyService(configService, ipintel)

        expect(
            (await policy.isDevicePostureAllowed({
                profile: { device: { postures: ['123', '1234'] } }
            } as any, {} as any, [], undefined)).result
        ).to.be.true;
        const posture1: DevicePosture = {
            id: '123',
            name: "windows10",
            isEnabled: true,
            labels: [],
            os: 'win32',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),

        }
        //platform does not match
        let result =

            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'linux'
                } as any
            );

        expect(result.result).to.be.false;
        expect(result.error).to.equal(ErrorCodesInternal.ErrDevicePostureOsTypeNotAllowed);

        //platform matches
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32'
                } as any
            )
        expect(result.result).to.be.true;

        //os version matches
        posture1.osVersions = [{ name: 'darwin', release: '1.2.3' }];
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32',
                    os: { version: '1.2.3' },
                } as any
            )
        expect(result.result).to.be.true;
        delete posture1.osVersions;//delete again

        ////antivirus check
        posture1.antivirusList = [{ name: 'general' }];
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32',
                    antiviruses: [{ isEnabled: false }]
                } as any
            )
        expect(result.result).to.be.false;

        ////firewall check
        posture1.firewallList = [{ name: 'general' }];
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32',
                    antiviruses: [{ isEnabled: true }],
                    firewalls: [{ isEnabled: false }]
                } as any
            )
        expect(result.result).to.be.false;

        ////disc encrytped check
        posture1.discEncryption = true;
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32',
                    antiviruses: [{ isEnabled: true }],
                    firewalls: [{ isEnabled: true }],
                    encryptedDiscs: [{ isEncrypted: false }]
                } as any
            )
        expect(result.result).to.be.false;

        ////mac list check
        posture1.macList = [{ value: 'abc' }]
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32',
                    antiviruses: [{ isEnabled: true }],
                    firewalls: [{ isEnabled: true }],
                    encryptedDiscs: [{ isEncrypted: true }],
                    macs: ['abcd']
                } as any
            )
        expect(result.result).to.be.false;

        ////serail list check
        posture1.serialList = [{ value: 'abc' }]
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32',
                    antiviruses: [{ isEnabled: true }],
                    firewalls: [{ isEnabled: true }],
                    encryptedDiscs: [{ isEncrypted: true }],
                    macs: ['abc'],
                    serial: { value: 'abcd' }
                } as any
            )
        expect(result.result).to.be.false;

        ////file list check
        posture1.filePathList = [{ path: 'abc' }]
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32',
                    antiviruses: [{ isEnabled: true }],
                    firewalls: [{ isEnabled: true }],
                    encryptedDiscs: [{ isEncrypted: true }],
                    macs: ['abc'],
                    serial: { value: 'abc' },
                    files: [{ path: 'dbcd' }]
                } as any
            )
        expect(result.result).to.be.false;

        ////process list check
        posture1.processList = [{ path: 'abc' }]
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32',
                    antiviruses: [{ isEnabled: true }],
                    firewalls: [{ isEnabled: true }],
                    encryptedDiscs: [{ isEncrypted: true }],
                    macs: ['abc'],
                    serial: { value: 'abc' },
                    files: [{ path: 'abc' }],
                    processes: [{ path: 'dbcd' }]
                } as any
            )
        expect(result.result).to.be.false;

        ////registry list check
        posture1.registryList = [{ path: 'abc' }]
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32',
                    antiviruses: [{ isEnabled: true }],
                    firewalls: [{ isEnabled: true }],
                    encryptedDiscs: [{ isEncrypted: true }],
                    macs: ['abc'],
                    serial: { value: 'abc' },
                    files: [{ path: 'abc' }],
                    processes: [{ path: 'abc' }],
                    registries: [{ path: 'abcd' }]
                } as any
            )
        expect(result.result).to.be.false;

        ////registry list check
        posture1.registryList = [{ path: 'abc' }]
        result =
            await policy.isDevicePostureAllowed(
                {
                    profile: { device: { postures: ['123', '1234'] } }
                } as any,
                {} as any,
                [
                    posture1
                ],
                {
                    platform: 'win32',
                    antiviruses: [{ isEnabled: true }],
                    firewalls: [{ isEnabled: true }],
                    encryptedDiscs: [{ isEncrypted: true }],
                    macs: ['abc'],
                    serial: { value: 'abc' },
                    files: [{ path: 'abc' }],
                    processes: [{ path: 'abc' }],
                    registries: [{ path: 'abc' }]
                } as any
            )
        expect(result.result).to.be.true;

    }).timeout(120000)

})

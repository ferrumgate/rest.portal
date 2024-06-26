import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { ConfigService } from '../src/service/configService';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';

import { IpIntelligenceSource } from '../src/model/ipIntelligence';
import { ESService } from '../src/service/esService';
import { InputService } from '../src/service/inputService';
import { IpIntelligenceService } from '../src/service/ipIntelligenceService';

chai.use(chaiHttp);
const expect = chai.expect;

function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete b.insertDate;
    delete b.updateDate;
    expect(a).to.deep.equal(b);
}
const ipApiComApiKey = '';
const ipDataCoApiKey = '';
const ipifyOrgApiKey = '';

describe.skip('ipIntelligenceService', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const configService = new ConfigService('kgWn7f1dtNOjuYdjezf0dR5I3HQIMNrGsUqthIsHHPoeqt', filename);
    const redisService = new RedisService();
    const inputService = new InputService();

    before(async () => {
        await configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await configService.saveConfigToFile();
        await configService.loadConfigFromFile();
    })
    beforeEach(async () => {
        await redisService.flushAll();
    })
    it('IPApiCom will throw error', async () => {
        const source: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            insertDate: '', name: 'ipapi.com', type: 'ipapi.com', updateDate: '',
            apiKey: ipApiComApiKey, isFreePlan: false
        }
        const esService = new ESService(configService);
        //await configService.saveIpIntelligenceSource(source);
        let errorOccured = false;
        try {
            const intel = new IpIntelligenceService(configService, redisService, inputService, esService);
            const result = await intel.check(source);
        } catch (err) {
            errorOccured = true;
        }
        expect(errorOccured).to.be.true;

    }).timeout(500000);

    it('IPApiCom', async () => {
        const source: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            insertDate: '', name: 'ipapi.com', type: 'ipapi.com', updateDate: '',
            apiKey: ipApiComApiKey, isFreePlan: true, isSecurityPlan: false
        }
        //await configService.saveIpIntelligenceSource(source);
        const esService = new ESService(configService);
        const intel = new IpIntelligenceService(configService, redisService, inputService, esService);
        const result = await intel.check(source);
        expect(result).exist;
        expect(result?.countryCode).exist;
        expect(result?.countryName).exist;

    }).timeout(500000);

    it('IpDataCo will throw error', async () => {
        const source: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            insertDate: '', name: 'ipdata.co', type: 'ipdata.co', updateDate: '',
            apiKey: '',
        }
        const esService = new ESService(configService);
        //await configService.saveIpIntelligenceSource(source);
        let errorOccured = false;
        try {
            const intel = new IpIntelligenceService(configService, redisService, inputService, esService);
            const result = await intel.check(source);
        } catch (err) {
            errorOccured = true;
        }
        expect(errorOccured).to.be.true;

    }).timeout(500000);

    it('IpDataCo', async () => {
        const source: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            insertDate: '', name: 'ipdata.co', type: 'ipdata.co', updateDate: '',
            apiKey: ipDataCoApiKey,
        }
        const esService = new ESService(configService);
        //await configService.saveIpIntelligenceSource(source);
        const intel = new IpIntelligenceService(configService, redisService, inputService, esService);
        const result = await intel.check(source);
        expect(result).exist;
        expect(result?.countryCode).exist;
        expect(result?.countryName).exist;

    }).timeout(500000);

    it('IpIfyOrg will throw error', async () => {
        const source: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            insertDate: '', name: 'ipify.org', type: 'ipify.org', updateDate: '',
            apiKey: 'adfasd',
        }
        const esService = new ESService(configService);
        //await configService.saveIpIntelligenceSource(source);
        let errorOccured = false;
        try {
            const intel = new IpIntelligenceService(configService, redisService, inputService, esService);
            const result = await intel.check(source);
        } catch (err) {
            errorOccured = true;
        }
        expect(errorOccured).to.be.true;

    }).timeout(500000);

    it('IpIfyOrg', async () => {
        const source: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            insertDate: '', name: 'ipify.org', type: 'ipify.org', updateDate: '',
            apiKey: ipifyOrgApiKey, isSecurityPlan: true
        }
        //await configService.saveIpIntelligenceSource(source);
        const esService = new ESService(configService);
        const intel = new IpIntelligenceService(configService, redisService, inputService, esService);
        const result = await intel.check(source);
        expect(result).exist;
        expect(result?.countryCode).exist;
        expect(result?.countryName).exist;

    }).timeout(500000);

    it('reConfigure', async () => {
        const source: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            insertDate: '', name: 'ipify.org', type: 'ipify.org', updateDate: '',
            apiKey: ipifyOrgApiKey, isSecurityPlan: true
        }
        await configService.saveIpIntelligenceSource(source);
        const esService = new ESService(configService);
        class Mock extends IpIntelligenceService {
            /**
             *
             */
            constructor(configService: ConfigService, redisService: RedisService, esService: ESService) {
                super(configService, redisService, inputService, esService);

            }
            getClass() {
                return this.api;
            }
        }
        const intel = new Mock(configService, redisService, esService);
        expect(intel.getClass()).not.exist;
        const result = await intel.reConfigure();
        expect(intel.getClass()).exist;

    }).timeout(500000);

    it('query', async () => {
        const source: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            insertDate: '', name: 'ipify.org', type: 'ipify.org', updateDate: '',
            apiKey: ipifyOrgApiKey, isSecurityPlan: true
        }
        await configService.saveIpIntelligenceSource(source);
        const esService = new ESService(configService);

        const intel = new IpIntelligenceService(configService, redisService, inputService, esService);
        const result = await intel.query('1.1.1.1');
        expect(result).exist;
        expect(result?.countryCode).exist;

    }).timeout(500000);

})


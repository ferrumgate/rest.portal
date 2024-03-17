
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { ConfigService } from '../src/service/configService';
import { Util } from '../src/util';
import { RedisService } from '../src/service/redisService';
import { GatewayDetail } from '../src/model/network';
import os from 'os';
import { GatewayService } from '../src/service/gatewayService';

import { IpIntelligenceSource } from '../src/model/ipIntelligence';
import { IpIntelligenceService } from '../src/service/ipIntelligenceService';
import { InputService } from '../src/service/inputService';
import { ESService } from '../src/service/esService';
import { FqdnIntelligenceSource } from '../src/model/fqdnIntelligence';
import { FqdnIntelligenceService } from '../src/service/fqdnIntelligenceService';


chai.use(chaiHttp);
const expect = chai.expect;


function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete b.insertDate;
    delete b.updateDate;
    expect(a).to.deep.equal(b);
}
const apiKey = '';

describe('fqdnIntelligenceService', async () => {
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



    /*  it('reConfigure', async () => {
         const source: FqdnIntelligenceSource = {
             id: Util.randomNumberString(),
             insertDate: '', name: 'brightcloud.org', type: 'brightcloud.org', updateDate: '',
             apiKey: apiKey, isSecurityPlan: true
         }
         await configService.saveFqdnIntelligenceSource(source);
         const esService = new ESService(configService);
         class Mock extends FqdnIntelligenceService {
            
    constructor(configService: ConfigService, redisService: RedisService, esService: ESService) {
        super(configService, redisService, inputService, esService);
    
    }
    getClass() {
        return this.service;
    }
    }
        const intel = new Mock(configService, redisService, esService);
    expect(intel.getClass()).not.exist;
    const result = await intel.reConfigure();
    expect(intel.getClass()).exist;
    
    
    }).timeout(500000); 
    */








})



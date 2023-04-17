
import chai, { util } from 'chai';
import chaiHttp from 'chai-http';
import fs, { read } from 'fs';
import { AppService } from '../src/service/appService';
import { IntelligenceLogService } from '../src/service/intelligenceLogService';
import { FqdnIntelligenceService } from '../src/service/fqdnIntelligenceService';
import { DomainIntelligenceBWItem } from '../src/model/domainIntelligence';
import { RedisService } from '../src/service/redisService';
import { SystemLogService } from '../src/service/systemLogService';
import { RedisConfigService } from '../src/service/redisConfigService';
import { Util } from '../src/util';



chai.use(chaiHttp);
const expect = chai.expect;




describe('intelligenceLogService', async () => {

    const redis = new RedisService();
    const redisStream = new RedisService();
    beforeEach(async () => {

        await redis.flushAll();
    })
    const encKey = 'u88aapisbdvmufeptows0a5l53sa1r3v';


    it('encrypt/decrypt', async () => {
        const systemlog = new SystemLogService(redis, redisStream, encKey, 'testme');
        const configService = new RedisConfigService(redis, redisStream, systemlog, encKey, 'testme2');
        const fqdn = new FqdnIntelligenceService(configService, redis, encKey);
        const testData = 'www.yahoo.com';
        const encStr = fqdn.encrypt(testData);
        const decStr = fqdn.decrypt(encStr.toString());
        //expect(decStr).to.equal(testData);


    }).timeout(10000);

    it('rSaveBigObj', async () => {
        const systemlog = new SystemLogService(redis, redisStream, encKey, 'testme');
        const configService = new RedisConfigService(redis, redisStream, systemlog, encKey, 'testme2');
        const fqdn = new FqdnIntelligenceService(configService, redis, encKey);
        const bwitem: DomainIntelligenceBWItem = {
            fqdn: 'www.yahoo.com', insertDate: new Date().toISOString()

        }
        await fqdn.rSaveBigObj('domainIntelligence/blackList', bwitem.fqdn, ['fqdn'], undefined, bwitem);
        const item = await fqdn.rGetWithBigObj(`domainIntelligence/blackList`, bwitem.fqdn, ['fqdn']);
        expect(item).exist;
        // expect(item).deep.equal(bwitem);



    }).timeout(10000);

    it('rDelBigObj', async () => {
        const systemlog = new SystemLogService(redis, redisStream, encKey, 'testme');
        const configService = new RedisConfigService(redis, redisStream, systemlog, encKey, 'testme2');
        const fqdn = new FqdnIntelligenceService(configService, redis, encKey);
        const bwitem: DomainIntelligenceBWItem = {
            fqdn: 'www.yahoo.com', insertDate: new Date().toISOString()

        }
        await fqdn.rSaveBigObj('domainIntelligence/blackList', bwitem.fqdn, ['fqdn'], undefined, bwitem);
        const item = await fqdn.rGetWithBigObj(`domainIntelligence/blackList`, bwitem.fqdn, ['fqdn']);
        expect(item).exist;
        //expect(item).deep.equal(bwitem);

        await fqdn.rDelBigObj('domainIntelligence/blackList', item, bwitem.fqdn);

        const item2 = await fqdn.rGetWithBigObj(`domainIntelligence/blackList`, bwitem.fqdn, ['fqdn']);
        //expect(item2).not.exist;




    }).timeout(10000);



    it('rSaveBigObj performance', async () => {
        const systemlog = new SystemLogService(redis, redisStream, encKey, 'testme');
        const configService = new RedisConfigService(redis, redisStream, systemlog, encKey, 'testme2');
        const fqdn = new FqdnIntelligenceService(configService, redis, encKey);
        let list = [];
        for (let i = 0; i < 100000; ++i) {
            const bwitem: DomainIntelligenceBWItem = {
                fqdn: Util.randomNumberString(32), insertDate: new Date().toISOString()

            }
            list.push(bwitem);
        }
        let start = Util.nanosecond();
        let pipeline = await redis.multi();
        for (const bwitem of list) {
            await fqdn.rSaveBigObj('domainIntelligence/blackList', bwitem.fqdn, ['fqdn'], undefined, bwitem, pipeline);
        }
        await pipeline.exec();
        let end = Util.nanosecond();

        console.log(`first save milisecond:${(end - start) / 1000 / 1000}`)

        //try again
        list = [];
        for (let i = 0; i < 100000; ++i) {
            const bwitem: DomainIntelligenceBWItem = {
                fqdn: Util.randomNumberString(32), insertDate: new Date().toISOString()

            }
            list.push(bwitem);
        }
        start = Util.nanosecond();
        pipeline = await redis.multi();
        for (const bwitem of list) {
            await fqdn.rSaveBigObj('domainIntelligence/blackList', bwitem.fqdn, ['fqdn'], undefined, bwitem, pipeline);
        }
        await pipeline.exec();
        end = Util.nanosecond();

        console.log(`second save milisecond:${(end - start) / 1000 / 1000}`)



    }).timeout(120000);


    it('rSaveBigObj getall multi performance', async () => {
        const systemlog = new SystemLogService(redis, redisStream, encKey, 'testme');
        const configService = new RedisConfigService(redis, redisStream, systemlog, encKey, 'testme2');
        const fqdn = new FqdnIntelligenceService(configService, redis, encKey);
        let list = [];
        for (let i = 0; i < 100000; ++i) {
            const bwitem: DomainIntelligenceBWItem = {
                fqdn: Util.randomNumberString(32), insertDate: new Date().toISOString()

            }
            list.push(bwitem);
        }
        let start = Util.nanosecond();
        let pipeline = await redis.multi();
        for (const bwitem of list) {
            await fqdn.rSaveBigObj('domainIntelligence/blackList', bwitem.fqdn, ['fqdn'], undefined, bwitem, pipeline);
        }
        await pipeline.exec();
        let end = Util.nanosecond();

        console.log(`first save milisecond:${(end - start) / 1000 / 1000}`)

        //get all

        start = Util.nanosecond();


        const items3 = await fqdn.rGetAllBigMulti('domainIntelligence/blackList', ['fqdn']);

        end = Util.nanosecond();

        console.log(`getall  multi len: ${items3.length} milisecond:${(end - start) / 1000 / 1000}`);



    }).timeout(120000);


    it('rGetWithBigObjs performance', async () => {
        const systemlog = new SystemLogService(redis, redisStream, encKey, 'testme');
        const configService = new RedisConfigService(redis, redisStream, systemlog, encKey, 'testme2');
        const fqdn = new FqdnIntelligenceService(configService, redis, encKey);
        let list = [];
        for (let i = 0; i < 100000; ++i) {
            const bwitem: DomainIntelligenceBWItem = {
                fqdn: Util.randomNumberString(32), insertDate: new Date().toISOString()

            }
            list.push(bwitem);
        }
        let start = Util.nanosecond();
        let pipeline = await redis.multi();
        for (const bwitem of list) {
            await fqdn.rSaveBigObj('domainIntelligence/blackList', bwitem.fqdn, ['fqdn'], undefined, bwitem, pipeline);
        }
        await pipeline.exec();
        let end = Util.nanosecond();

        console.log(`first save milisecond:${(end - start) / 1000 / 1000}`)

        //get all

        start = Util.nanosecond();


        const items3 = await fqdn.rGetWithBigObjs('domainIntelligence/blackList', list.map(x => x.fqdn), ['fqdn']);

        end = Util.nanosecond();

        console.log(`rGetWithBigObjs  multi len: ${items3.length} milisecond:${(end - start) / 1000 / 1000}`);



    }).timeout(120000);




})



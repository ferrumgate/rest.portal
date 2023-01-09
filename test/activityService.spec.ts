
import chai from 'chai';
import chaiHttp from 'chai-http';
import * as odiff from 'deep-object-diff'
import { RedisService } from '../src/service/redisService';
import { AuditService, ObjectDiffer } from '../src/service/auditService';
import { AuditLog } from '../src/model/auditLog';
import { Util } from '../src/util';
import { ESService } from '../src/service/esService';
import { ActivityService } from '../src/service/activityService';



chai.use(chaiHttp);
const expect = chai.expect;




describe('activityService', async () => {

    beforeEach(async () => {

    })


    const streamKey = '/logs/activity';
    const esHost = 'https://192.168.88.250:9200';
    const esUser = "elastic";
    const esPass = '123456';
    it('save', async () => {
        const es = new ESService(esHost, esUser, esPass);
        const redis = new RedisService();
        await redis.delete(streamKey)
        let log = {
            id: 1
        } as any;
        const service = new ActivityService(redis, es);
        await service.save(log);
        await Util.sleep(1000);
        const items = await redis.xread(streamKey, 10, '0', 1000);
        expect(items.length).to.equal(1);
        const item = items[0];
        const data = Buffer.from(item.val, 'base64')
        expect(data).exist;
        const obj = Util.jdecode(data);// JSON.parse(data);
        expect(obj).deep.equal(log);
        await service.stop();


    }).timeout(20000);

    it('trimStream', async () => {
        const es = new ESService(esHost, esUser, esPass);
        const redis = new RedisService();
        await redis.delete(streamKey)
        let log = {
            id: 1
        } as any;
        const service = new ActivityService(redis, es);
        await service.save(log);
        await Util.sleep(1000);
        const items = await redis.xread(streamKey, 10, '0', 1000);
        expect(items.length).to.equal(1);
        await Util.sleep(1000);
        await service.trimStream(new Date().getTime().toString());
        const items2 = await redis.xread(streamKey, 10, '0', 1000);
        expect(items2.length).to.equal(0);
        await service.stop();


    }).timeout(20000);




})



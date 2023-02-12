
import chai from 'chai';
import chaiHttp from 'chai-http';
import * as odiff from 'deep-object-diff'
import { RedisService } from '../src/service/redisService';
import { AuditService, ObjectDiffer } from '../src/service/auditService';
import { AuditLog } from '../src/model/auditLog';
import { Util } from '../src/util';
import { ESService } from '../src/service/esService';
import { ActivityService } from '../src/service/activityService';
import { ConfigService } from '../src/service/configService';




chai.use(chaiHttp);
const expect = chai.expect;




describe('activityService', async () => {
    const streamKey = '/logs/activity';
    const host = 'https://192.168.88.250:9200';
    const user = 'elastic';
    const pass = '123456';
    const config = new ConfigService('fljvc7rm1xfo37imbu3ryc5mfbh9jpm5', `/tmp/${Util.randomNumberString()}`)
    beforeEach(async () => {
        await config.setES({ host: host, user: user, pass: pass })

    })



    it('save', async () => {

        const es = new ESService(config, host, user, pass);
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
        const data = Buffer.from(item.val, 'base64url')
        expect(data).exist;
        const obj = Util.jdecode(data);// JSON.parse(data);
        expect(obj).deep.equal(log);
        await service.stop();


    }).timeout(20000);

    it('trimStream', async () => {
        const es = new ESService(config, host, user, pass);
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



import chai from 'chai';
import chaiHttp from 'chai-http';
import { ActivityService } from '../src/service/activityService';
import { ConfigService } from '../src/service/configService';
import { ESService } from '../src/service/esService';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';
import { esHost, esPass, esUser } from './common.spec';

chai.use(chaiHttp);
const expect = chai.expect;

describe('activityService', async () => {
    const streamKey = '/logs/activity';

    const config = new ConfigService('fljvc7rm1xfo37imbu3ryc5mfbh9jpm5', `/tmp/${Util.randomNumberString()}`)
    beforeEach(async () => {
        await config.setES({ host: esHost, user: esUser, pass: esPass })

    })

    it('save', async () => {

        const es = new ESService(config, esHost, esUser, esPass);
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
        const es = new ESService(config, esHost, esUser, esPass);
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


import chai from 'chai';
import { ConfigService } from '../src/service/configService';
import { ESServiceExtended } from '../src/service/esService';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';
import { esHost, esPass, esUser } from './common.spec';

const expect = chai.expect;

describe('esServiceExtended ', async () => {
    const redis = new RedisService();
    beforeEach(async () => {

        await redis.flushAll();

    })

    it('connect', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        await configService.setES({ host: esHost, user: esUser, pass: esPass });
        const es = new ESServiceExtended(configService, esHost, esUser, esPass);
        await Util.sleep(1000);
        const indexes = await es.getAllIndexes();

    }).timeout(20000);

})
import chai from 'chai';
import chaiHttp from 'chai-http';
import { ConfigService } from '../src/service/configService';
import { RateLimitService } from '../src/service/rateLimitService';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';

chai.use(chaiHttp);
const expect = chai.expect;

describe('rateLimitService integration', () => {
    const redisService = new RedisService("localhost:6379");
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const configService = new ConfigService('9p5jV0DqEpMeTXrrF0QmoRMNDaZQ6DziIPPlI0IlpwcqnfYk', filename)
    beforeEach(async () => {
        await redisService.flushAll();
    })

    after(async () => {

    })

    it('check limit', async () => {
        //will not throw ex
        const ratelimit = new RateLimitService(configService, redisService);
        for (let index = 0; index < 5; index++) {
            await ratelimit.check('1.1.1.1', 'checksystem', 10);
        }

    }).timeout(60000);
    it('check limit will throw exception', async () => {
        let errorOccured = false;
        try {
            const ratelimit = new RateLimitService(configService, redisService);
            for (let index = 0; index < 150; index++) {
                await ratelimit.check('1.1.1.1', 'checksystem', 10);
            }
        } catch (err) {
            errorOccured = true;
        }
        expect(errorOccured).to.be.true;

    }).timeout(60000);

})
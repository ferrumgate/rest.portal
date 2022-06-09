
import chai from 'chai';
import chaiHttp from 'chai-http';
import { RedisService } from '../src/service/redisService';
import { RateLimitService } from '../src/service/rateLimitService';
import { ConfigService } from '../src/service/configService';

chai.use(chaiHttp);
const expect = chai.expect;

describe('rateLimitService integration', () => {
    const redisService = new RedisService("localhost:6379");
    const configService = new ConfigService('9p5jV0DqEpMeTXrrF0QmoRMNDaZQ6DziIPPlI0IlpwcqnfYk')
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
            for (let index = 0; index < 15; index++) {
                await ratelimit.check('1.1.1.1', 'checksystem', 10);
            }
        } catch (err) {
            errorOccured = true;
        }
        expect(errorOccured).to.be.true;

    }).timeout(60000);

})
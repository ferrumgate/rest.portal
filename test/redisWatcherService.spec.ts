import chai from 'chai';
import chaiHttp from 'chai-http';
import { RedisService } from '../src/service/redisService';
import { RedisWatcherService } from '../src/service/redisWatcherService';

chai.use(chaiHttp);
const expect = chai.expect;

describe('redisWatcherService ', async () => {
    const simpleRedis = new RedisService('localhost:6379');
    beforeEach(async () => {
        const simpleRedis = new RedisService('localhost:6379');
        await simpleRedis.flushAll();
    })

    it('isMaster', async () => {
        const redis = new RedisWatcherService(simpleRedis);
        expect(redis.isMaster).to.be.false;
        await redis.checkRedisIsMaster();
        expect(redis.isMaster).to.be.true;

    }).timeout(5000);

    it('start', async () => {

        const redis = new RedisWatcherService(simpleRedis);
        expect(redis.isMaster).to.be.false;
        await redis.start();

        expect(redis.isMaster).to.be.true;

    }).timeout(5000);

});
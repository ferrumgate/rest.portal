import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { RedisConfigService } from '../src/service/redisConfigService';
import { RedisService } from '../src/service/redisService';
import { SystemLogService } from '../src/service/systemLogService';

chai.use(chaiHttp);
const expect = chai.expect;

describe('PKIService ', async () => {
    const encKey = 'u88aapisbdvmufeptows0a5l53sa1r3v';
    const redis = new RedisService();
    const redisStream = new RedisService();
    const systemlog = new SystemLogService(redis, redisStream, encKey, 'testme');
    const configService = new RedisConfigService(redis, redisStream, systemlog, encKey, 'testme2');

    beforeEach(async () => {

        await redis.flushAll();
    })
    function readFileSync(path: string) {
        return fs.readFileSync(path).toString();
    }

})


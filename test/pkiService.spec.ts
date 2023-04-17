
import chai from 'chai';
import chaiHttp from 'chai-http';
import { ConfigService } from '../src/service/configService';
import { RedisService } from '../src/service/redisService';

import { PKIService } from '../src/service/pkiService';
import { RedisConfigService } from '../src/service/redisConfigService';
import { SystemLogService } from '../src/service/systemLogService';
import { Util } from '../src/util';
import fs from 'fs';


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




import chai from 'chai';
import chaiHttp from 'chai-http';
import * as odiff from 'deep-object-diff'
import { RedisService } from '../src/service/redisService';
import { AuditService, ObjectDiffer } from '../src/service/auditService';
import { AuditLog } from '../src/model/auditLog';
import { Util } from '../src/util';
import { ESService } from '../src/service/esService';
import { ConfigService } from '../src/service/configService';
import { RedLockService } from '../src/service/redLockService';



chai.use(chaiHttp);
const expect = chai.expect;




describe('redLockService ', async () => {
    const redis = new RedisService();
    beforeEach(async () => {
        await redis.flushAll();
    })
    it('lock/release', async () => {
        let isLocked = false;
        let isReleased = false;
        const locker = new RedLockService(redis);
        locker.events.on('acquired', () => isLocked = true);
        locker.events.on('released', () => isReleased = true);
        await locker.lock('/lock/test', 2000, 1000);
        await Util.sleep(5000);

        expect(isLocked).to.be.true;
        await locker.release();
        expect(isReleased).to.be.true;
        expect(await redis.get('/lock/test', false)).to.be.null;


    }).timeout(15000);


    it('lock/release multi check', async () => {
        let isLocked = false;
        let isReleased = false;
        const locker = new RedLockService(redis);
        locker.events.on('acquired', () => isLocked = true);
        locker.events.on('released', () => isReleased = true);
        await locker.lock('/lock/test', 2000, 1000);
        await Util.sleep(5000);
        expect(isLocked).to.be.true;


        let isLocked2 = false;
        let isReleased2 = false;
        const locker2 = new RedLockService(redis);
        locker2.events.on('acquired', () => isLocked2 = true);
        locker2.events.on('released', () => isReleased2 = true);
        await Util.sleep(5000);
        expect(isLocked2).to.be.false;
        await locker.release();
        await locker2.release();
        expect(isReleased).to.be.true;
        expect(isReleased2).to.be.false;



    }).timeout(15000);
})
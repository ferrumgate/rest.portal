
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
import { WatchItem, WatchService } from '../src/service/watchService';



chai.use(chaiHttp);
const expect = chai.expect;




describe('watchService ', async () => {
    const redis = new RedisService();
    const redisStream = new RedisService();
    beforeEach(async () => {
        await redis.flushAll();
    })
    it('read/write', async () => {
        const watcher = new WatchService(redis, redisStream, 'pos', '/log/abc');
        await watcher.write('test');

        const watcher2 = new WatchService(redis, redisStream, 'pos', '/log/abc', '0');
        let written = '';
        let time = 0;
        watcher2.events.on('data', (data: WatchItem<string>) => {
            written = data.val;
            time = data.time;
        })
        const data = await watcher2.read();
        expect(written).to.equal('test');
        expect(time).exist;

    }).timeout(15000);

    it('trim', async () => {
        const watcher = new WatchService(redis, redisStream, 'pos', '/log/abc', '$', 1000);
        await watcher.write('test');
        await Util.sleep(2000);
        await watcher.trim();
        const watcher2 = new WatchService(redis, redisStream, 'pos', '/log/abc', '0');
        let written = '';
        watcher2.events.on('data', (data: any) => {
            written = data.val;

        })

        const data = await watcher2.read();
        expect(written).to.equal('');//nothing readed

    }).timeout(15000);


})
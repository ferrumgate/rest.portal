import chai from 'chai';
import chaiHttp from 'chai-http';
import { RedisService } from '../src/service/redisService';
import { WatchGroupService, WatchItem, WatchService } from '../src/service/watchService';
import { Util } from '../src/util';

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

    it('read/write encrytped', async () => {
        const watcher = new WatchService(redis, redisStream, 'pos', '/log/abc', undefined, undefined, 'x4dzssxovbrlfbs45y0rzvg9fw3fnjdg', 1000);
        await watcher.write('test');

        const watcher2 = new WatchService(redis, redisStream, 'pos', '/log/abc', '0', undefined, 'x4dzssxovbrlfbs45y0rzvg9fw3fnjdg', 1000);
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

describe('watchGroupService ', async () => {
    const redis = new RedisService();
    const redisStream = new RedisService();
    beforeEach(async () => {
        await redis.flushAll();
    })
    it('read/write', async () => {

        const watcher = new WatchService(redis, redisStream, '/log/abc', 'pos', '0');
        await watcher.write('test');
        let written = '';
        let time = 0;
        const watcher2 = new WatchGroupService(redis, redisStream, 'de', 'de', '/log/abc');
        watcher2.events.on('data', (data: WatchItem<string>) => {
            written = data.val;
            time = data.time;
        })

        const data = await watcher2.read();
        expect(written).to.equal('test');
        expect(time).exist;

    }).timeout(15000);

})
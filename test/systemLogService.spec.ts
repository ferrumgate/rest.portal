
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs, { read } from 'fs';
import { AppService } from '../src/service/appService';
import { SystemLogService } from '../src/service/systemLogService';
import { RedisService, Util } from '../src/lib';


chai.use(chaiHttp);
const expect = chai.expect;




describe('systemLogService', async () => {

    const redis = new RedisService();
    const redisStream = new RedisService();
    beforeEach(async () => {

        await redis.flushAll();
    })
    it('write/read', async () => {

        const log = new SystemLogService(redis, redisStream);
        let readedData = null;
        log.watcher.events.on('data', (data: any) => {
            readedData = data;
        })
        await log.startWatch();
        await log.start();
        await log.write({ 'path': '/test', type: 'put', 'val': { id: 1 } });
        await Util.sleep(5000);
        expect(readedData).exist;
        console.log(readedData);
        expect((readedData as any).val.type).to.equal('put');
        await log.stopWatch();
        await log.stop();
        await Util.sleep(3000);

    }).timeout(10000);

    it('write/read encrypted', async () => {

        const log = new SystemLogService(redis, redisStream, 'es7lcqz73ftr5f846oy8evpmivhzkvqb', 'test2');
        let readedData = null;
        log.watcher.events.on('data', (data: any) => {
            readedData = data;
        })
        await log.startWatch();
        await log.start();
        await log.write({ 'path': '/test', type: 'put', 'val': { id: 1 } });
        await Util.sleep(5000);
        expect(readedData).exist;
        console.log(readedData);
        expect((readedData as any).val.type).to.equal('put');
        await log.stopWatch();
        await log.stop();
        await Util.sleep(3000);

    }).timeout(50000);

})



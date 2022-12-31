
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs, { read } from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { SystemLogService } from '../src/service/systemLogService';
import { RedisService, Util } from '../src/lib';


chai.use(chaiHttp);
const expect = chai.expect;




describe('systemLogService', async () => {

    const redis = new RedisService();
    const redisStream = new RedisService();
    beforeEach(async () => {
        await (app.appService as AppService).redisService.flushAll();
    })
    it('write/read', async () => {

        const log = new SystemLogService(redis, redisStream);
        let readedData = null;
        log.logWatcher.events.on('data', (data: any) => {
            readedData = data;
        })
        await log.logWatcher.start();
        await log.start();
        await log.write({ 'path': '/test', type: 'put', 'val': { id: 1 } });
        await Util.sleep(2000);
        expect(readedData).exist;
        console.log(readedData);
        expect((readedData as any).val.type).to.equal('put');

    }).timeout(5000);

})



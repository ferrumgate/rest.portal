
import chai from 'chai';
import chaiHttp from 'chai-http';
import { RedisService } from '../src/service/redisService';
import { Util } from '../src/util';

import { RBAC, RBACDefault } from '../src/model/rbac';
import { RedisConfigService } from '../src/service/redisConfigService';
import { RedisConfigWatchService } from '../src/service/redisConfigWatchService';
import { Group } from '../src/model/group';
import { User } from '../src/model/user';




chai.use(chaiHttp);
const expect = chai.expect;

describe('redisConfigWatchService ', async () => {
    const redis = new RedisService();

    const encryptKey = Util.randomNumberString(32);
    beforeEach(async () => {
        await redis.flushAll();
    })

    async function saveTestData(redisConfig: RedisConfigService) {


        await redisConfig.saveUser({ id: '1', username: 'ferrum' } as User);
        await redisConfig.saveGroup({ id: '1', name: 'gr' } as Group)
    }
    it('isReady', async () => {
        const redisConfig = new RedisConfigService(new RedisService(), new RedisService(), encryptKey, 'test', '/tmp/abc');
        await redisConfig.init();
        await saveTestData(redisConfig);

        const watch = new RedisConfigWatchService(new RedisService(), new RedisService(), encryptKey, 'test2', '/tmp/abcd');
        let isError = false;
        try {
            await watch.getUrl();
        } catch (err) {
            isError = true
        }
        expect(isError).to.be.true;

    }).timeout(15000);


    it('isReadonly', async () => {
        const redisConfig = new RedisConfigService(new RedisService(), new RedisService(), encryptKey, 'test', '/tmp/abc');
        await redisConfig.init();
        await saveTestData(redisConfig);

        const watch = new RedisConfigWatchService(new RedisService(), new RedisService(), encryptKey, 'test2', '/tmp/abcd');
        await watch.start();
        await Util.sleep(3000);
        let isError = false;
        try {
            await watch.getUrl();
        } catch (err) {
            isError = true
        }
        expect(isError).to.be.false;

        isError = false;
        try {
            await watch.setUrl('abc');
        } catch (err) {
            isError = true;
        }
        expect(isError).to.be.true;
        await watch.stop();

    }).timeout(15000);


    it('default system settings must exit', async () => {
        const redisConfig = new RedisConfigService(new RedisService(), new RedisService(), encryptKey, 'test', '/tmp/abc');
        await redisConfig.init();


        const watch = new RedisConfigWatchService(new RedisService(), new RedisService(), encryptKey, 'test2', '/tmp/abcd');
        await watch.start();
        await saveTestData(redisConfig);
        await Util.sleep(3000);
        watch.isReady();;//throws errors if not ready
        expect(await watch.getUser('1')).exist;

        await watch.stop();

    }).timeout(150000);


    it('events', async () => {
        const redisConfig = new RedisConfigService(new RedisService(), new RedisService(), encryptKey, 'test', '/tmp/abc');
        await redisConfig.init();


        const watcher = new RedisConfigWatchService(new RedisService(), new RedisService(), encryptKey, 'test2', '/tmp/abcd');
        let eventsReceived = false;
        watcher.watch.on('configChanged', (data: any) => {
            eventsReceived = true;
        })
        await watcher.start();
        await saveTestData(redisConfig);
        await Util.sleep(3000);
        expect(eventsReceived).to.be.true;
        await watcher.stop();

    }).timeout(150000);


})



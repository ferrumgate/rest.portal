
//docker run --net=host --name redis --rm -d redis


import chai from 'chai';
import chaiHttp from 'chai-http';

import fs, { watch } from 'fs';
import { RedisService } from '../src/service/redisService';

import { RedisConfigWatchCachedService } from '../src/service/redisConfigWatchCachedService';
import { SystemLogService } from '../src/service/systemLogService';
import { Tunnel } from '../src/model/tunnel';
import { RedisConfigService } from '../src/service/redisConfigService';
import { Util } from '../src/util';


chai.use(chaiHttp);
const expect = chai.expect;

const tmpfolder = '/tmp/ferrumtest';
const encKey = 'unvjukt3i62bxkr0d6f0lpvlho5fvqb1'
describe('RedisConfigWatchCachedService', () => {
    const redis = new RedisService();

    beforeEach(async () => {
        await redis.flushAll();
        if (fs.existsSync(tmpfolder))
            await fs.rmSync(tmpfolder, { recursive: true, force: true });
        fs.mkdirSync(tmpfolder);
    })


    class MockConfig extends RedisConfigWatchCachedService {
        /**
         *
         */
        constructor(systemlog?: SystemLogService) {
            super(new RedisService(), new RedisService(),
                systemlog || new SystemLogService(new RedisService(), new RedisService(), encKey), true, encKey)

        }
        getCache() {
            return this.nodeCache;
        }
        getConfig() { return this.config };
    }

    async function getSampleTunnel() {
        const tunnel1: Tunnel = {
            id: '123', tun: 'ferrum2', assignedClientIp: '1.2.3.4',
            authenticatedTime: new Date().toISOString(), clientIp: '3.4.5.6',
            gatewayId: '12345', serviceNetwork: '172.10.0.0/16', userId: '12', trackId: 5
        }
        const tunnel2: Tunnel = {
            id: '1234', tun: 'ferrum2', assignedClientIp: '1.2.3.4',
            authenticatedTime: new Date().toISOString(), clientIp: '3.4.5.6',
            gatewayId: '123456', serviceNetwork: '172.10.0.0/16', userId: '12', trackId: 5
        }
        return { val1: tunnel1, val2: tunnel2 };
    }


    it('checkifDataExits', async () => {
        const systemlog = new SystemLogService(new RedisService(), new RedisService(), encKey);
        //save default settings like user and network
        const redisConfig = new RedisConfigService(new RedisService(), new RedisService(), systemlog, encKey);
        await redisConfig.init();
        await Util.sleep(1000);
        //load again
        const config = new MockConfig(systemlog);
        await config.start();
        await Util.sleep(1000);
        const conf = config.getConfig();
        const cache = config.getCache();

        expect(cache.get(conf.users[0].id)).exist;



        expect(cache.get(conf.networks[0].id)).exist;





    }).timeout(100000)


    it('checkifDataExits', async () => {
        const systemlog = new SystemLogService(new RedisService(), new RedisService(), encKey);
        const config = new MockConfig(systemlog);
        await config.start();
        await Util.sleep(1000);
        await systemlog.write({ path: '/config/users', type: 'put', val: { id: 1, test: '2' } });
        await systemlog.write({ path: '/config/groups', type: 'put', val: { id: 2, test: '3' } });
        await systemlog.write({ path: '/config/networks', type: 'put', val: { id: 3, test: '4' } });
        await systemlog.write({ path: '/config/gateways', type: 'put', val: { id: 4, test: '5' } });
        await systemlog.write({ path: '/config/services', type: 'put', val: { id: 5, test: '6' } });
        await Util.sleep(1000);
        const conf = config.getConfig();
        const cache = config.getCache();

        expect(cache.get(conf.users[0].id)).exist;
        expect(cache.get<any>(conf.users[0].id).test).to.equal('2')

        expect(cache.get(conf.groups[0].id)).exist;
        expect(cache.get<any>(conf.groups[0].id).test).to.equal('3')

        expect(cache.get(conf.networks[0].id)).exist;
        expect(cache.get<any>(conf.networks[0].id).test).to.equal('4')

        expect(cache.get(conf.gateways[0].id)).exist;
        expect(cache.get<any>(conf.gateways[0].id).test).to.equal('5')

        expect(cache.get(conf.services[0].id)).exist;
        expect(cache.get<any>(conf.services[0].id).test).to.equal('6')



    }).timeout(100000)



    it('check data after delete', async () => {
        const systemlog = new SystemLogService(new RedisService(), new RedisService(), encKey);
        const config = new MockConfig(systemlog);
        await config.start();
        await Util.sleep(1000);
        await systemlog.write({ path: '/config/users', type: 'put', val: { id: 1, test: '2' } });
        await systemlog.write({ path: '/config/groups', type: 'put', val: { id: 2, test: '3' } });
        await systemlog.write({ path: '/config/networks', type: 'put', val: { id: 3, test: '4' } });
        await systemlog.write({ path: '/config/gateways', type: 'put', val: { id: 4, test: '5' } });
        await systemlog.write({ path: '/config/services', type: 'put', val: { id: 5, test: '6' } });
        await Util.sleep(1000);

        const conf = config.getConfig();
        const cache = config.getCache();

        expect(cache.get(conf.users[0].id)).exist;
        expect(cache.get(conf.groups[0].id)).exist;
        expect(cache.get(conf.networks[0].id)).exist;
        expect(cache.get(conf.gateways[0].id)).exist;
        expect(cache.get(conf.services[0].id)).exist;

        await systemlog.write({ path: '/config/users', type: 'del', val: { id: 1, test: '2' } });
        await systemlog.write({ path: '/config/groups', type: 'del', val: { id: 2, test: '3' } });
        await systemlog.write({ path: '/config/networks', type: 'del', val: { id: 3, test: '4' } });
        await systemlog.write({ path: '/config/gateways', type: 'del', val: { id: 4, test: '5' } });
        await systemlog.write({ path: '/config/services', type: 'del', val: { id: 5, test: '6' } });
        await Util.sleep(1000);
        expect(cache.keys().length).to.equal(0);


    }).timeout(100000)



})
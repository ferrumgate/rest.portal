
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { InputService } from '../src/service/inputService';
import { RestfullException } from '../src/restfullException';
import { ErrorCodes } from '../src/restfullException';
import { RedisService } from '../src/service/redisService';
import { ConfigService } from '../src/service/configService';
import { Util } from '../src/util';
import { Network } from '../src/model/network';
import { Gateway } from '../src/model/network';
import { ConfigPublicRoom, ConfigPublicListener, ConfigRequest, ConfigResponse } from '../src/service/system/configPublicListener';



chai.use(chaiHttp);
const expect = chai.expect;


async function createSampleData(): Promise<ConfigService> {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    //first create a config and save to a file
    let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
    let network: Network = {
        id: '6hiryy8ujv3n',
        name: 'default',
        labels: [],
        clientNetwork: '10.10.0.0/16',
        serviceNetwork: '172.16.0.0/24',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()
    };
    await configService.saveNetwork(network);

    let gateway: Gateway = {
        id: '231a0932',
        name: 'myserver',
        labels: [],
        isEnabled: true,
        networkId: network.id,
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()
    }
    await configService.saveGateway(gateway);


    let gateway2: Gateway = {
        id: 'aaa231a0932',
        name: 'myserver',
        labels: [],
        isEnabled: true,
        networkId: '213sa',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()
    }
    await configService.saveGateway(gateway2);
    return configService;
}

describe('configPublicRoom ', async () => {

    beforeEach(async () => {
        const simpleRedis = new RedisService('localhost:6379');
        await simpleRedis.flushAll();
    })

    it('getServiceNetworkByGatewayId', async () => {
        const config = await createSampleData();
        const room = new ConfigPublicRoom('231a0932', config);
        let isError = false;
        try { await room.getServiceNetworkByGatewayId('someid'); } catch (err) { isError = true; }

        isError = false
        try { await room.getServiceNetworkByGatewayId('someid', 'theotherid') } catch (err) { isError = true };

        isError = false
        try { await room.getServiceNetworkByGatewayId('someid', 'aaa231a0932') } catch (err) { isError = true };

        const result = await room.getServiceNetworkByGatewayId('someid', '231a0932')
        expect(result.id).to.equal('someid');
        expect(result.isError).to.be.undefined;
        expect(result.result).to.equal('172.16.0.0/24');

    }).timeout(5000);

    it('executeRequest', async () => {
        const config = await createSampleData();
        const room = new ConfigPublicRoom('231a0932', config);
        let isError = false;
        try { await room.executeRequest({ hostId: 'someid' } as any); } catch (err) { isError = true; }

        isError = false
        try { await room.executeRequest({ id: '221', hostId: '231a0932', func: 'notfound' } as any) } catch (err) { isError = true };

        const result = await room.executeRequest({ id: '23232', hostId: '231a0932', func: 'getServiceNetworkByGatewayId', params: ['231a0932'] });

        expect(result.id).to.equal('23232');
        expect(result.isError).to.be.undefined;
        expect(result.result).to.equal('172.16.0.0/24');

    }).timeout(5000);


    it('processWaitList', async () => {
        const simpleRedis = new RedisService('localhost:6379');
        const config = await createSampleData();
        const room = new ConfigPublicRoom('231a0932', config);

        await room.waitList.push({ id: '10', hostId: '231a0932', func: 'getServiceNetworkByGatewayId', params: ['231a0932'] });
        await room.processWaitList();
        expect(room.waitList.length).to.equal(0);
        let pos = '0';
        const result = await simpleRedis.xread('/query/host/231a0932', 100, pos, 1000);
        expect(result.length).to.be.equal(1);
        pos = result[0].xreadPos;
        const response = JSON.parse(Buffer.from(result[0].data, 'base64').toString()) as ConfigResponse;
        expect(response.id).to.equal('10');
        expect(response.isError).to.undefined;
        expect(response.result).to.equal('172.16.0.0/24');


    }).timeout(5000);

})


describe('configPublicListener ', async () => {

    beforeEach(async () => {
        const simpleRedis = new RedisService('localhost:6379');
        await simpleRedis.flushAll();
    })

    it('checkRedisRole', async () => {
        //const simpleRedis = new RedisService('localhost:6379');
        const config = await createSampleData();
        const listener = new ConfigPublicListener(config);

        expect(listener.isRedisMaster).to.be.false;
        await listener.checkRedisRole();
        expect(listener.isRedisMaster).to.be.true;
    })
    it('executeMessage', async () => {

        const config = await createSampleData();
        const listener = new ConfigPublicListener(config);
        const msg: ConfigRequest = {
            id: 'adfaf', func: 'getServiceId', hostId: 'somehost', params: []
        }
        await listener.executeMessage('channe;', Buffer.from(JSON.stringify(msg)).toString('base64'));
        expect(listener.roomList.size).to.equal(1);
        expect(listener.cache.get('somehost')).exist;

    })
})



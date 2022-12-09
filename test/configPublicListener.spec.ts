
import chai from 'chai';
import chaiHttp from 'chai-http';
import { RedisService } from '../src/service/redisService';
import { ConfigService } from '../src/service/configService';
import { Util } from '../src/util';
import { Network } from '../src/model/network';
import { Gateway } from '../src/model/network';
import { ConfigPublicRoom, ConfigPublicListener, ConfigRequest, ConfigResponse } from '../src/service/system/configPublicListener';
import { Service } from '../src/model/service';

import chaiExclude from 'chai-exclude';
import { RedisWatcher } from '../src/service/system/redisWatcher';

chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);



async function createSampleData(): Promise<any> {
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

    let service: Service = {
        id: Util.randomNumberString(),
        name: 'mysql-dev',
        isEnabled: true,
        labels: [],
        host: '1.2.3.4',
        networkId: network.id,
        tcp: 3306, assignedIp: '1.3',
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString(),
        count: 1

    }
    //add
    await configService.saveService(service);
    return { gateway, gateway2, network, service, configService };
}

describe('configPublicRoom ', async () => {

    beforeEach(async () => {
        const simpleRedis = new RedisService('localhost:6379');
        await simpleRedis.flushAll();
    })


    it('getGatewayById', async () => {
        const { gateway, gateway2, network, service, configService } = await createSampleData();
        const room = new ConfigPublicRoom('231a0932', configService);

        let resp = await room.getGatewayById('someid');
        expect(resp.error).to.be.undefined;
        expect(resp.result).to.be.undefined;


        resp = await room.getGatewayById('someid', 'theotherid');
        expect(resp.result).to.be.undefined;
        expect(resp.isError).to.be.undefined;


        resp = await room.getGatewayById('someid', 'baaa231a0932')
        expect(resp.result).to.be.undefined;
        expect(resp.isError).to.be.undefined;

        const result = await room.getGatewayById('someid', '231a0932')
        expect(result.id).to.equal('someid');
        expect(result.isError).to.be.undefined;
        expect(result.result).to.excluding(['insertDate', 'updateDate']).deep.equal(gateway);

    }).timeout(5000);

    it('getNetworkByGatewayId', async () => {
        const { gateway, gateway2, network, service, configService } = await createSampleData();
        const room = new ConfigPublicRoom('231a0932', configService);

        let resp = await room.getNetworkByGatewayId('someid');
        expect(resp.error).to.be.undefined;
        expect(resp.result).to.be.undefined;


        resp = await room.getNetworkByGatewayId('someid', 'theotherid');
        expect(resp.result).to.be.undefined;
        expect(resp.isError).to.be.undefined;


        const result = await room.getNetworkByGatewayId('someid', '231a0932')
        expect(result.id).to.equal('someid');
        expect(result.isError).to.be.undefined;
        expect(result.result).to.excluding(['insertDate', 'updateDate']).deep.equal(network);

    }).timeout(5000);


    it('getService', async () => {
        const { gateway, gateway2, network, service, configService } = await createSampleData();
        const room = new ConfigPublicRoom('231a0932', configService);

        let resp = await room.getService('someid');
        expect(resp.error).to.be.undefined;
        expect(resp.result).to.be.undefined;


        resp = await room.getService('someid', 'theotherid');
        expect(resp.result).to.be.undefined;
        expect(resp.isError).to.be.undefined;


        const result = await room.getService('someid', service.id)
        expect(result.id).to.equal('someid');
        expect(result.isError).to.be.undefined;
        expect(result.result).to.excluding(['insertDate', 'updateDate']).deep.equal(service);

    }).timeout(5000);

    it('getServicesByGatewayId', async () => {
        const { gateway, gateway2, network, service, configService } = await createSampleData();
        const room = new ConfigPublicRoom('231a0932', configService);

        let resp = await room.getServicesByGatewayId('someid');
        expect(resp.error).to.be.undefined;
        expect(resp.result.length).to.equal(0);


        resp = await room.getServicesByGatewayId('someid', 'theotherid');
        expect(resp.error).to.be.undefined;
        expect(resp.result.length).to.equal(0);


        const result = await room.getServicesByGatewayId('someid', gateway.id);
        expect(result.id).to.equal('someid');
        expect(result.isError).to.be.undefined;
        expect(result.result[0]).to.excluding(['insertDate', 'updateDate']).deep.equal(service);

    }).timeout(5000);




    it('executeRequest', async () => {
        const { gateway, gateway2, network, service, configService } = await createSampleData();
        const room = new ConfigPublicRoom('231a0932', configService);
        let isError = false;
        try { await room.executeRequest({ gatewayId: 'someid' } as any); } catch (err) { isError = true; }

        isError = false
        try { await room.executeRequest({ id: '221', gatewayId: '231a0932', func: 'notfound' } as any) } catch (err) { isError = true };

        const result = await room.executeRequest({ id: '23232', gatewayId: '231a0932', func: 'getNetworkByGatewayId', params: ['231a0932'] });

        expect(result.id).to.equal('23232');
        expect(result.isError).to.be.undefined;
        expect(result.result.serviceNetwork).to.equal('172.16.0.0/24');

    }).timeout(5000);


    it('processWaitList', async () => {
        const simpleRedis = new RedisService('localhost:6379');
        const { gateway, gateway2, network, service, configService } = await createSampleData();
        const room = new ConfigPublicRoom('231a0932', configService);

        await room.waitList.push({ id: '10', gatewayId: '231a0932', func: 'getNetworkByGatewayId', params: ['231a0932'] });
        await room.processWaitList();
        expect(room.waitList.length).to.equal(0);
        let pos = '0';
        const result = await simpleRedis.xread('/query/gateway/231a0932', 100, pos, 1000);
        expect(result.length).to.be.equal(1);
        pos = result[0].xreadPos;
        const response = JSON.parse(Buffer.from(result[0].data, 'base64').toString()) as ConfigResponse;
        expect(response.id).to.equal('10');
        expect(response.isError).to.undefined;
        expect(response.result.serviceNetwork).to.equal('172.16.0.0/24');


    }).timeout(5000);

})


describe('configPublicListener ', async () => {

    beforeEach(async () => {
        const simpleRedis = new RedisService('localhost:6379');
        await simpleRedis.flushAll();
    })


    it('executeMessage', async () => {

        const { gateway, gateway2, network, service, configService } = await createSampleData();
        const watcher = new RedisWatcher('localhost:6379');
        await watcher.start();
        const listener = new ConfigPublicListener(configService, new RedisService('localhost:6379'),
            watcher);
        const msg: ConfigRequest = {
            id: 'adfaf', func: 'getServiceId', gatewayId: 'somehost', params: []
        }
        await listener.executeMessage('channe;', Buffer.from(JSON.stringify(msg)).toString('base64'));
        expect(listener.roomList.size).to.equal(1);
        expect(listener.cache.get('somehost')).exist;

    })
})



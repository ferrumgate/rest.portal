
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { ConfigService } from '../src/service/configService';
import { Gateway, Network } from '../src/model/network';
import { authorize, getNetworkByHostId } from '../src/api/commonApi';
import { Util } from '../src/util';



chai.use(chaiHttp);
const expect = chai.expect;




describe('commonApi', async () => {

    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    beforeEach(async () => {
        if (fs.existsSync(filename))
            fs.rmSync(filename);
    })
    it('getNetworkByHostId throws Error because of hostId is empty', async () => {

        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);

        let exception = false;
        try {
            await getNetworkByHostId(configService, '');
        } catch (err) {
            exception = true;
        }
        expect(exception).to.be.true;


    }).timeout(5000);
    it('getNetworkByHostId throws Error because of no gateway', async () => {

        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let exception = false;
        try {
            await getNetworkByHostId(configService, 'fakegateway');
        } catch (err) {
            exception = true;
        }
        expect(exception).to.be.true;

    }).timeout(5000);


    it('getNetworkByHostId throws Error because of gateway is not joined or active', async () => {

        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            clientNetwork: '10.0.0.0/24',
            serviceNetwork: '172.18.0.0/24'
        }
        const gateway: Gateway = {
            id: 'w20kaaoe',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: false
        }
        await configService.saveNetwork(net);
        await configService.saveGateway(gateway);

        let exception = false;
        try {
            await getNetworkByHostId(configService, gateway.id);
        } catch (err) {
            exception = true;
        }
        expect(exception).to.be.true;

    }).timeout(5000);

    it('getNetworkByHostId throws Error because of gateway network not found', async () => {

        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            clientNetwork: '10.0.0.0/24',
            serviceNetwork: '172.18.0.0/24'
        }
        const gateway: Gateway = {
            id: 'w20kaaoe',
            name: 'aserver',
            labels: [],
            networkId: net.id + '111',
            isEnabled: false
        }
        await configService.saveNetwork(net);
        await configService.saveGateway(gateway);

        let exception = false;
        try {
            await getNetworkByHostId(configService, gateway.id);
        } catch (err) {
            exception = true;
        }
        expect(exception).to.be.true;

    }).timeout(5000);


    it('authorize test to Admin right', async () => {

        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const user = {
            username: 'useradmin',
            groupIds: [],
            id: 'admin',
            name: 'admin',
            source: 'local',
            roleIds: ['Admin'],
            isLocked: false, isVerified: true,
            password: Util.bcryptHash('ferrumgate'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await configService.saveUser(user);

        const user2 = {
            username: 'useradmin2',
            groupIds: [],
            id: 'admin2',
            name: 'admin2',
            source: 'local',
            roleIds: ['User'],
            isLocked: false, isVerified: true,
            password: Util.bcryptHash('ferrumgate'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        await configService.saveUser(user2);
        //authorize admin
        let isNextCalled = false;
        let req = {
            currentUser: {
                id: 'admin'
            },
            appService: {
                configService: configService
            }
        }
        await authorize(req, {}, () => { isNextCalled = true; }, ['Admin']);
        expect(isNextCalled).to.be.true;

        // authorize admin will throw exception
        isNextCalled = false;
        let isException = false;
        req = {
            currentUser: {
                id: 'admin2'
            },
            appService: {
                configService: configService
            }
        }
        try {
            await authorize(req, {}, () => { isNextCalled = true; }, ['Admin']);
        } catch (err) { isException = true; }
        expect(isException).to.be.true;
        expect(isNextCalled).to.be.false;

    }).timeout(5000);



});
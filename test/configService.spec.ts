
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs, { read } from 'fs';
import { ConfigService } from '../src/service/configService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Gateway, Network } from '../src/model/network';


chai.use(chaiHttp);
const expect = chai.expect;


describe('configService', async () => {

    const filename = '/tmp/config.yaml';
    beforeEach((done) => {
        if (fs.existsSync(filename))
            fs.rmSync(filename);
        done();
    })

    it('saveConfigToFile', async () => {

        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        configService.saveConfigToFile();
        expect(fs.existsSync(filename));


    });
    it('loadConfigFromFile', async () => {

        //save it first
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid2',
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        configService.saveConfigToFile();
        expect(fs.existsSync(filename));

        let result = configService.loadConfigFromFile();
        //default user added
        expect(configService.config.users.find(x => x.id === 'someid2')?.id).to.equal('someid2');

    });

    it('saveConfigToString', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        configService.saveConfigToFile();
        expect(fs.existsSync(filename));
        const str = configService.saveConfigToString()
        const readed = fs.readFileSync(filename).toString();
        expect(readed).to.equal(str);

    });
    it('getUserByEmail', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        const user = await configService.getUserByUsername('hamza.kilic@ferrumgate.com');
        delete aUser.password;
        expect(user).to.deep.include(aUser);

    });

    it('getUserByEmailAndPass', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: Util.bcryptHash('passwordWithHash'), groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        const user = await configService.getUserByUsernameAndPass('hamza.kilic@ferrumgate.com', 'passwordWithHash');
        delete aUser.password;
        expect(user).to.deep.include(aUser);

        const user2 = await configService.getUserByUsernameAndPass('hamza.kilic@ferrumgate.com', 'passwordWithHash2');

        expect(user2).to.be.undefined;

    });
    it('getUserById', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        const user = await configService.getUserById('someid');
        delete aUser.password;
        expect(user).to.deep.include(aUser);

    });
    it('saveUser', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        let fakeUser = {
            ...aUser
        }
        fakeUser.id = 'test';
        await configService.saveUser(fakeUser);
        const userDb = await configService.getUserByUsername('hamza.kilic@ferrumgate.com');
        expect(userDb?.id).to.equal('someid');

    });

    it('getUserByApiKey', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: '6hiryy8ujv3n',
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            apiKey: '1fviqq286bmcm',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        const userDb = await configService.getUserByApiKey('1fviqq286bmcm');
        expect(userDb?.id).to.equal('6hiryy8ujv3n');

    });


    it('setNetwork getNetwork getNetworkByName', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let network: Network = {
            id: '6hiryy8ujv3n',
            name: 'default2',
            labels: [],
            clientNetwork: '10.10.0.0/16',
            serviceNetwork: '172.16.0.0/24'
        };

        await configService.setNetwork(network);
        const networkDb = await configService.getNetwork(network.id);
        expect(networkDb).to.deep.include(network);
        const networkDb2 = await configService.getNetworkByName('default2');
        expect(networkDb2).to.deep.include(network);

    });

    it('getNetworkByHostname', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let network: Network = {
            id: '6hiryy8ujv3n',
            name: 'default',
            labels: [],
            clientNetwork: '10.10.0.0/16',
            serviceNetwork: '172.16.0.0/24'
        };

        let gateway: Gateway = {
            id: '231a0932',
            name: 'myserver',
            labels: [],
            isEnabled: 1,
            networkId: network.id
        }

        await configService.setNetwork(network);
        await configService.setGateway(gateway);
        const networkDb = await configService.getNetworkByHost(gateway.id);
        expect(networkDb).to.deep.include(network);

    });


    it('deleteNetwork', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let network: Network = {
            id: '6hiryy8ujv3n',
            name: 'default',
            labels: [],
            clientNetwork: '10.10.0.0/16',
            serviceNetwork: '172.16.0.0/24'
        };

        let gateway: Gateway = {
            id: '231a0932',
            name: 'myserver',
            labels: [],
            isEnabled: 1,
            networkId: network.id
        }

        await configService.setNetwork(network);
        await configService.setGateway(gateway);
        await configService.deleteNetwork(network.id);
        const net = await configService.getNetwork(network.id)
        expect(net).not.exist;
        const gate = await configService.getGateway(gateway.id);
        expect(gate?.networkId).to.equal('');

    });

    it('getGateway setGateway', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);

        let gateway: Gateway = {
            id: '231a0932',
            name: 'myserver',
            labels: [],
            isEnabled: 1,

            networkId: ''
        }


        await configService.setGateway(gateway);
        const gatewayDb = await configService.getGateway(gateway.id);
        expect(gatewayDb).to.deep.include(gateway);

    });
    it('deleteGateway', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);

        let gateway: Gateway = {
            id: '231a0932',
            name: 'myserver',
            labels: [],
            isEnabled: 1,

            networkId: ''
        }


        await configService.setGateway(gateway);
        await configService.deleteGateway(gateway.id);
        const gatewayDb = await configService.getGateway(gateway.id);
        expect(gatewayDb).not.exist;


    });



});

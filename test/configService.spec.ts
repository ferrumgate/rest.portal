
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs, { read } from 'fs';
import { ConfigService } from '../src/service/configService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Gateway, Network } from '../src/model/network';
import { AuthOAuth, AuthCommon, AuthLdap, AuthSaml, AuthLocal, BaseOAuth, BaseLocal } from '../src/model/authSettings';
import { Group } from '../src/model/group';


chai.use(chaiHttp);
const expect = chai.expect;


describe('configService', async () => {

    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    beforeEach((done) => {

        if (fs.existsSync(filename))
            fs.rmSync(filename);
        done();
    })

    it('saveConfigToFile', async () => {

        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.users = [];
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
        configService.config.users = [];
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
        configService.config.users = [];
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
        configService.config.users = [];
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
        configService.config.users = [];
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
        configService.config.users = [];
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




    it('getUsersBy', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.users = [];
        let aUser: User = {
            id: 'id1',
            username: 'hamza1@ferrumgate.com',
            name: 'test1', source: 'local', labels: ['test1'],
            password: Util.bcryptHash('passwordWithHash'), groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        let aUser2: User = {
            id: 'id2',
            username: 'hamza2@ferrumgate.com',
            name: 'test2', source: 'google', labels: ['test2'],
            password: Util.bcryptHash('passwordWithHash'), groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };
        configService.config.users.push(aUser2);

        let aUser3: User = {
            id: 'id3',
            username: 'hamza3@ferrumgate.com',
            name: 'test3', source: 'linkedin', labels: ['test3'],
            password: Util.bcryptHash('passwordWithHash'), groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser3);

        let aUser4: User = {
            id: 'id4',
            username: 'hamza4@ferrumgate.com',
            name: 'test4', source: 'linkedin', labels: ['test4'],
            password: Util.bcryptHash('passwordWithHash'), groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser4);
        //added 4 users
        //get all
        const list = await configService.getUsersBy();
        expect(list.items.length).to.be.equal(4);
        expect(list.total).to.be.equal(4);

        //get 1 page
        const list2 = await configService.getUsersBy(1, 2)
        expect(list2.items.length).to.be.equal(2);
        expect(list2.total).to.be.equal(4);

        //get page 2
        const list3 = await configService.getUsersBy(2, 2)
        expect(list3.items.length).to.be.equal(0);
        expect(list3.total).to.be.equal(4);

        //search by name
        const list4 = await configService.getUsersBy(0, 0, 'hamza3')
        expect(list4.items.length).to.be.equal(1);
        expect(list4.total).to.be.equal(1);
        //search by source
        const list5 = await configService.getUsersBy(0, 0, 'linked')
        expect(list5.items.length).to.be.equal(2);
        expect(list5.total).to.be.equal(2);



    });

    it('saveUser', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.users = [];
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
        configService.config.users = [];
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


    it('saveNetwork getNetwork getNetworkByName', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);

        let network: Network = {
            id: '6hiryy8ujv3n',
            name: 'default2',
            labels: [],
            clientNetwork: '10.10.0.0/16',
            serviceNetwork: '172.16.0.0/24'
        };

        await configService.saveNetwork(network);
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
            isEnabled: true,
            networkId: network.id
        }

        await configService.saveNetwork(network);
        await configService.saveGateway(gateway);
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
            isEnabled: true,
            networkId: network.id
        }

        await configService.saveNetwork(network);
        await configService.saveGateway(gateway);
        await configService.deleteNetwork(network.id);
        const net = await configService.getNetwork(network.id)
        expect(net).not.exist;
        const gate = await configService.getGateway(gateway.id);
        expect(gate?.networkId).to.equal('');

    });

    it('getGateway saveGateway', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);

        let gateway: Gateway = {
            id: '231a0932',
            name: 'myserver',
            labels: [],
            isEnabled: true,

            networkId: ''
        }


        await configService.saveGateway(gateway);
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
            isEnabled: true,

            networkId: ''
        }


        await configService.saveGateway(gateway);
        await configService.deleteGateway(gateway.id);
        const gatewayDb = await configService.getGateway(gateway.id);
        expect(gatewayDb).not.exist;
    });

    it('authSettingsCommon', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);

        let common: AuthCommon = {
            bla: 'test'
        }
        await configService.setAuthSettingsCommon(common);
        const returned = await configService.getAuthSettingsCommon() as any;
        expect(returned).to.be.exist;
        expect(returned.bla).exist;

    });

    it('authSettingsOAuth', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.auth = {
            common: {}, local: {} as any
        }
        let oauth: BaseOAuth = {
            name: 'google',
            baseType: 'oauth',
            type: 'google',
            id: 'jkj;adfa',
            clientId: 'akdfa',
            clientSecret: 'adfa',
            tags: [],
            isEnabled: true
        }
        //add
        await configService.addAuthSettingOAuth(oauth);

        const returned = await configService.getAuthSettingOAuth();
        expect(returned.providers[0]).to.deep.equal(oauth);
        //delete
        await configService.deleteAuthSettingOAuth(oauth.id);
        const returned2 = await configService.getAuthSettingOAuth();
        expect(returned2.providers.length).to.equal(0);
        // adding same id
        await configService.addAuthSettingOAuth(oauth);
        const cloned = Util.clone(oauth);
        await configService.addAuthSettingOAuth(oauth);
        const returned3 = await configService.getAuthSettingOAuth();
        expect(returned3.providers.length).to.equal(1);


    });

    it('authSettingsLocal', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.auth = {
            common: {}, local: {} as any
        }
        let local: BaseLocal = {
            name: 'google',
            baseType: 'oauth',
            type: 'google',
            id: 'jkj;adfa',
            tags: [],
            isForgotPassword: true,
            isRegister: false,
            isEnabled: true

        }
        //add
        await configService.setAuthSettingsLocal(local);

        const returned = await configService.getAuthSettingsLocal();
        expect(returned).to.deep.equal(local);


    });


    it('getGroup', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.groups = [];
        let group: Group = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: []

        }
        //add
        await configService.saveGroup(group);

        const returned = await configService.getGroup(group.id);
        expect(returned).to.deep.equal(group);


    });

    it('getGroupBySearch', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.groups = [];
        let group: Group = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2']

        }
        //add
        await configService.saveGroup(group);

        let group2: Group = {
            id: Util.randomNumberString(),
            name: 'south',
            isEnabled: true,
            labels: ['test']

        }
        //add
        await configService.saveGroup(group2);

        const returned = await configService.getGroupsBySearch('test');
        expect(returned.length).to.equal(2);

        const returned2 = await configService.getGroupsBySearch('abo');
        expect(returned2.length).to.be.equal(0);


    });


    it('getGroupsAll', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.groups = [];
        let group: Group = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2']

        }
        //add
        await configService.saveGroup(group);

        let group2: Group = {
            id: Util.randomNumberString(),
            name: 'south',
            isEnabled: true,
            labels: ['test']

        }
        //add
        await configService.saveGroup(group2);

        const returned = await configService.getGroupsAll();
        expect(returned.length).to.be.equal(2);
        expect(returned[0]).to.deep.equal(group);

    });

    it('saveGroup', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.groups = [];
        let group: Group = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2']

        }
        //add
        await configService.saveGroup(group);

        group.name = 'north2';
        //add
        await configService.saveGroup(group);

        const returned = await configService.getGroup(group.id)

        expect(returned).to.deep.equal(group);

    });

    it('deleteGroup', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);

        configService.config.groups = [];
        let group: Group = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2']

        }
        //add
        await configService.saveGroup(group);

        //save a user
        let aUser: User = {
            id: 'someid',
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: Util.bcryptHash('passwordWithHash'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            groupIds: [group.id]

        };

        configService.config.users.push(aUser);

        await configService.deleteGroup(group.id);

        const returned = await configService.getGroup(group.id)

        expect(returned).not.exist;
        const user = await configService.getUserById(aUser.id)
        expect(user?.groupIds.length).to.equal(0);

    });



});

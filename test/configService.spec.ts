
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { ConfigService } from '../src/service/configService';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Gateway, Network } from '../src/model/network';
import { AuthCommon, BaseOAuth, BaseLocal } from '../src/model/authSettings';
import { Group } from '../src/model/group';
import { Service } from '../src/model/service';
import { AuthenticationRule } from '../src/model/authenticationPolicy';
import { AuthorizationRule } from '../src/model/authorizationPolicy';
import { ConfigEvent } from '../src/model/config';

import chaiExclude from 'chai-exclude';

chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);


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
        await configService.saveConfigToFile();
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
        await configService.saveConfigToFile();
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
        await configService.saveConfigToFile();
        expect(fs.existsSync(filename));
        const str = await configService.saveConfigToString()
        const readed = fs.readFileSync(filename).toString();


    });
    it('getUserByUsername', async () => {

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

    it('getUserByUsernameAndPass', async () => {

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
            password: Util.bcryptHash('passwordWithHash'), groupIds: ['g1', 'g2'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        let aUser2: User = {
            id: 'id2',
            username: 'hamza2@ferrumgate.com',
            name: 'test2', source: 'google', labels: ['test2'],
            password: Util.bcryptHash('passwordWithHash'), groupIds: ['g2'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };
        configService.config.users.push(aUser2);

        let aUser3: User = {
            id: 'id3',
            username: 'hamza3@ferrumgate.com',
            roleIds: ['user'],
            name: 'test3', source: 'linkedin', labels: ['test3'],
            password: Util.bcryptHash('passwordWithHash'), groupIds: ['g3'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser3);

        let aUser4: User = {
            id: 'id4',
            username: 'hamza4@ferrumgate.com',
            name: 'test4', source: 'linkedin', labels: ['test4'],
            password: Util.bcryptHash('passwordWithHash'), groupIds: ['g1', 'g2'],
            roleIds: ['admin'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isVerified: true,
            isLocked: true,
            is2FA: true,
            isEmailVerified: true,


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

        //search by id
        const list6 = await configService.getUsersBy(0, 0, '', ['id4']);
        expect(list6.items.length).to.be.equal(1);

        //search by group id
        const list7 = await configService.getUsersBy(0, 0, '', [], ['g3']);
        expect(list7.items.length).to.be.equal(1);

        //search by role id
        const list8 = await configService.getUsersBy(0, 0, '', [], [], ['admin']);
        expect(list8.items.length).to.be.equal(1);

        //search by is2fa
        const list9 = await configService.getUsersBy(0, 0, '', [], [], [], true);
        expect(list9.items.length).to.be.equal(1);

        //search by isVerified
        const list10 = await configService.getUsersBy(0, 0, '', [], [], [], undefined, true);
        expect(list10.items.length).to.be.equal(1);

        //search by isLocked
        const list11 = await configService.getUsersBy(0, 0, '', [], [], [], undefined, undefined, true);
        expect(list11.items.length).to.be.equal(1);

        //search by isEmailVerified
        const list12 = await configService.getUsersBy(0, 0, '', [], [], [], undefined, undefined, undefined, true);
        expect(list12.items.length).to.be.equal(1);


    });


    it('getUserByRoleIds', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.users = [];
        let aUser: User = {
            id: 'someid',
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: Util.bcryptHash('passwordWithHash'),
            groupIds: [], roleIds: ['Admin'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        const users = await configService.getUserByRoleIds(['Admin']);

        expect(users.length).to.be.equal(1);

        const users2 = await configService.getUserByRoleIds(['User']);

        expect(users2.length).to.be.equal(0);

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

    it('deleteUser', async () => {

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
        await configService.deleteUser(fakeUser.id);
        const userDb = await configService.getUser(fakeUser.id)
        expect(userDb).not.exist;

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
            serviceNetwork: '172.16.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        await configService.saveNetwork(network);
        const networkDb = await configService.getNetwork(network.id);
        expect(networkDb).to.excluding(['insertDate', 'updateDate']).deep.equal(network);
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
            serviceNetwork: '172.16.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        let gateway: Gateway = {
            id: '231a0932',
            name: 'myserver',
            labels: [],
            isEnabled: true,
            networkId: network.id,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }

        await configService.saveNetwork(network);
        await configService.saveGateway(gateway);
        const networkDb = await configService.getNetworkByGateway(gateway.id);
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
            serviceNetwork: '172.16.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        let gateway: Gateway = {
            id: '231a0932',
            name: 'myserver',
            labels: [],
            isEnabled: true,
            networkId: network.id,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
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

            networkId: '',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }


        await configService.saveGateway(gateway);
        const gatewayDb = await configService.getGateway(gateway.id);
        expect(gatewayDb).to.excluding(['insertDate', 'updateDate']).deep.equal(gateway);

    });
    it('deleteGateway', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);

        let gateway: Gateway = {
            id: '231a0932',
            name: 'myserver',
            labels: [],
            isEnabled: true,

            networkId: '',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
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
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        //add
        await configService.addAuthSettingOAuth(oauth);

        const returned = await configService.getAuthSettingOAuth();
        expect(returned.providers[0]).to.excluding(['insertDate', 'updateDate']).deep.equal(oauth);
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
            tags: [],
            isForgotPassword: true,
            isRegister: false,
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.setAuthSettingsLocal(local);

        const returned = await configService.getAuthSettingsLocal();
        expect(returned).to.excluding(['insertDate', 'updateDate']).deep.equal(local);


    });


    it('getGroup', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.groups = [];
        let group: Group = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveGroup(group);

        const returned = await configService.getGroup(group.id);
        expect(returned).to.excluding(['insertDate', 'updateDate']).deep.equal(group);


    });

    it('getGroupBySearch', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.groups = [];
        let group: Group = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveGroup(group);

        let group2: Group = {
            id: Util.randomNumberString(),
            name: 'south',
            isEnabled: true,
            labels: ['test'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

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
            labels: ['test2'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveGroup(group);

        let group2: Group = {
            id: Util.randomNumberString(),
            name: 'south',
            isEnabled: true,
            labels: ['test'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveGroup(group2);

        const returned = await configService.getGroupsAll();
        expect(returned.length).to.be.equal(2);
        expect(returned[0]).to.excluding(['insertDate', 'updateDate']).deep.equal(group);

    });

    it('saveGroup', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.groups = [];
        let group: Group = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveGroup(group);

        group.name = 'north2';
        //add
        await configService.saveGroup(group);

        const returned = await configService.getGroup(group.id)

        expect(returned).to.excluding(['insertDate', 'updateDate']).deep.equal(group);

    });

    it('deleteGroup', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);

        configService.config.groups = [];
        let group: Group = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

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


    ///// service 

    it('getService', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.services = [];
        let service: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],
            host: '1.2.3.4',
            networkId: 'abcd',
            tcp: 3306, assignedIp: '1.3',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service);

        const returned = await configService.getService(service.id);
        expect(returned).to.excluding(['insertDate', 'updateDate']).deep.equal(service);


    });

    it('getServicesBy', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.services = [];
        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],
            host: '1.2.3.4',
            networkId: 'abcd',
            tcp: 3306,
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service1);

        let service2: Service = {
            id: Util.randomNumberString(),
            name: 'remote-desktop-dev',
            isEnabled: true,
            labels: ['test'],
            host: '192.168.10.10',
            networkId: 'abcd',
            tcp: 3306,
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service2);

        const returned = await configService.getServicesBy('dev');
        expect(returned.length).to.equal(2);

        const returned2 = await configService.getServicesBy('remote222');
        expect(returned2.length).to.be.equal(0);

        const returned3 = await configService.getServicesBy('test');
        expect(returned3.length).to.be.equal(1);

        const returned4 = await configService.getServicesBy('192.168');
        expect(returned4.length).to.be.equal(1);


        const returned5 = await configService.getServicesBy('', ['abcd']);
        expect(returned5.length).to.be.equal(2);

        const returned6 = await configService.getServicesBy('', [], [service2.id]);
        expect(returned6.length).to.be.equal(1);



    });

    it('getServicesByNetworkId', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.services = [];
        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],
            host: '1.2.3.4',
            networkId: 'abcd',
            tcp: 3306,
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service1);

        let service2: Service = {
            id: Util.randomNumberString(),
            name: 'remote-desktop-dev',
            isEnabled: true,
            labels: ['test'],
            host: '192.168.10.10',
            networkId: 'dabc',
            tcp: 3306,
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service2);

        const returned = await configService.getServicesByNetworkId('dabc');
        expect(returned.length).to.equal(1);


    });


    it('getServicesAll', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.services = [];
        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],
            host: '1.2.3.4',
            networkId: 'abcd',
            tcp: 3306,
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service1);

        let service2: Service = {
            id: Util.randomNumberString(),
            name: 'remote-desktop-dev',
            isEnabled: true,
            labels: ['test'],
            host: '192.168.10.10',
            networkId: 'abcd',
            tcp: 3306,
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service2);

        const returned = await configService.getServicesBy();
        expect(returned.length).to.be.equal(2);
        expect(returned[0]).to.excluding(['insertDate', 'updateDate']).deep.equal(service1);

    });

    it('saveService', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.services = [];
        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],
            host: '1.2.3.4',
            networkId: 'abcd',
            tcp: 3306,
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service1);

        service1.name = 'north2';
        //add
        await configService.saveService(service1);

        const returned = await configService.getService(service1.id)

        expect(returned).to.excluding(['insertDate', 'updateDate']).deep.equal(service1);

    });

    it('deleteService', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);

        configService.config.groups = [];
        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],
            host: '1.2.3.4',
            networkId: 'abcd',
            tcp: 3306,
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service1);


        await configService.deleteService(service1.id);

        const returned = await configService.getService(service1.id)

        expect(returned).not.exist;


    });

    //authenticationPolicy

    it('saveAthenticationPolicyAddRule', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        //add
        await configService.saveAuthenticationPolicyRule(rule);

        const policy = await configService.getAuthenticationPolicyUnsafe();
        expect(policy.rules.find(x => x.id == rule.id)).to.exist;


    });
    it('getAuthenticationPolicy', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        configService.config.authenticationPolicy.rules.push(rule);


        const policy = await configService.getAuthenticationPolicy();
        expect(policy.rules.find(x => x.id == rule.id)).to.exist;
        expect(policy.rules.length).to.equal(1);

    });

    it('getAuthenticationPolicyUnsafe', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        configService.config.authenticationPolicy.rules.push(rule);


        const policy = await configService.getAuthenticationPolicyUnsafe();
        expect(policy.rules.find(x => x.id == rule.id)).to.exist;
        expect(policy.rules.length).to.equal(1);

    });

    it('deleteAuthenticationPolicyRule', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        configService.config.authenticationPolicy.rules.push(rule);


        await configService.deleteAuthenticationPolicyRule(rule.id);
        expect(configService.config.authenticationPolicy.rules.find(x => x.id == rule.id)).to.not.exist;
        expect(configService.config.authenticationPolicy.rules.length).to.equal(0);

    });


    it('updateAuthenticationRulePos', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];
        let rule1: AuthenticationRule = {
            id: '1',
            name: "zero trust1",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        configService.config.authenticationPolicy.rules.push(rule1);

        let rule2: AuthenticationRule = {
            id: '2',
            name: "zero trust2",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        configService.config.authenticationPolicy.rules.push(rule2);


        let rule3: AuthenticationRule = {
            id: '3',
            name: "zero trust3",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        configService.config.authenticationPolicy.rules.push(rule3);
        const policy = configService.config.authenticationPolicy;

        await configService.updateAuthenticationRulePos(rule1.id, 0, 0);
        expect(policy.rules[0].id).to.be.equal('1');
        expect(policy.rules[1].id).to.be.equal('2');
        expect(policy.rules[2].id).to.be.equal('3');


        await configService.updateAuthenticationRulePos(rule1.id, 0, 5);
        expect(policy.rules[0].id).to.be.equal('2');
        expect(policy.rules[1].id).to.be.equal('3');
        expect(policy.rules[2].id).to.be.equal('1');

        await configService.updateAuthenticationRulePos(rule1.id, 2, 1);
        expect(policy.rules[0].id).to.be.equal('2');
        expect(policy.rules[1].id).to.be.equal('1');
        expect(policy.rules[2].id).to.be.equal('3');

        await configService.updateAuthenticationRulePos(rule1.id, 1, 0);
        expect(policy.rules[0].id).to.be.equal('1');
        expect(policy.rules[1].id).to.be.equal('2');
        expect(policy.rules[2].id).to.be.equal('3');

        let errrored = false;
        try {
            await configService.updateAuthenticationRulePos(rule1.id, 1, 5);
        } catch (err) {
            errrored = true;
        }
        expect(errrored).to.be.true;





    });




    //authorizationPolicy

    it('saveAuthorizationPolicyAddRule', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authorizationPolicy.rules = [];
        let rule: AuthorizationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            serviceId: 'some service',
            profile: { is2FA: true },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        //add
        await configService.saveAuthorizationPolicyRule(rule);

        const policy = await configService.getAuthorizationPolicyUnsafe();
        expect(policy.rules.find(x => x.id == rule.id)).to.exist;


    });
    it('getAuthorizationPolicy', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        let rule: AuthorizationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            serviceId: 'some service',
            profile: { is2FA: true, },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        //add
        await configService.saveAuthorizationPolicyRule(rule);

        const policy = await configService.getAuthorizationPolicy();
        expect(policy.rules.find(x => x.id == rule.id)).to.exist;
        expect(policy.rules.length).to.equal(1);

    });

    it('getAuthorizationPolicyUnsafe', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authorizationPolicy.rules = [];
        let rule: AuthorizationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            serviceId: 'some service',
            profile: { is2FA: true, },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        //add
        await configService.saveAuthorizationPolicyRule(rule);


        const policy = await configService.getAuthorizationPolicyUnsafe();
        expect(policy.rules.find(x => x.id == rule.id)).to.exist;
        expect(policy.rules.length).to.equal(1);

    });

    it('deleteAuthorizationPolicyRule', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authorizationPolicy.rules = [];
        let rule: AuthorizationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",

            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            serviceId: 'some service',
            profile: { is2FA: true },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        //add

        configService.config.authorizationPolicy.rules.push(rule);


        await configService.deleteAuthorizationPolicyRule(rule.id);
        expect(configService.config.authorizationPolicy.rules.find(x => x.id == rule.id)).to.not.exist;
        expect(configService.config.authorizationPolicy.rules.length).to.equal(0);

    });


    it('triggerUserDeleted', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let eventDatas: ConfigEvent[] = [];
        configService.events.on('changed', (data: ConfigEvent) => {
            eventDatas.push(data)
        })

        let aUser: User = {
            id: Util.randomNumberString(),
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);

        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        let rule: AuthorizationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",

            networkId: 'networkId',
            userOrgroupIds: [aUser.id],
            serviceId: 'some service',
            profile: { is2FA: true, },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        //add

        configService.config.authorizationPolicy.rules.push(rule);


        let rule2: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: [aUser.id],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }

        //add
        configService.config.authenticationPolicy.rules.push(rule2);

        await configService.deleteUser(aUser.id);
        expect(configService.config.authorizationPolicy.rules.find(x => x.userOrgroupIds.includes(aUser.id))).to.not.exist;
        expect(configService.config.authenticationPolicy.rules.find(x => x.userOrgroupIds.includes(aUser.id))).to.not.exist;

        expect(eventDatas.length).to.equal(5);

        expect(eventDatas[0].type).to.equal('updated')
        expect(eventDatas[0].path).to.equal('/authenticationPolicy/rules');
        expect(eventDatas[0].data.before.id).exist;
        expect(eventDatas[0].data.after.id).exist;

        expect(eventDatas[1].type).to.equal('updated')
        expect(eventDatas[1].path).to.equal('/authenticationPolicy');
        expect(eventDatas[1].data).not.exist;

        expect(eventDatas[2].type).to.equal('updated')
        expect(eventDatas[2].path).to.equal('/authorizationPolicy/rules');
        expect(eventDatas[2].data.before.id).exist;
        expect(eventDatas[2].data.after.id).exist;

        expect(eventDatas[3].type).to.equal('updated')
        expect(eventDatas[3].path).to.equal('/authorizationPolicy');
        expect(eventDatas[3].data).not.exist;

        expect(eventDatas[4].type).to.equal('deleted');
        expect(eventDatas[4].path).to.equal('/users');
        expect(eventDatas[4].data.before.id).exist;
        expect(eventDatas[4].data.after).not.exist;




    });


    it('triggerUserSavedOrUpdated', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let eventDatas: ConfigEvent[] = [];
        configService.events.on('changed', (data: ConfigEvent) => {
            eventDatas.push(data)
        })

        let aUser: User = {
            id: Util.randomNumberString(),
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        await configService.saveUser(aUser);


        aUser.name = 'changed';

        await configService.saveUser(aUser);


        expect(eventDatas.length).to.equal(2);
        expect(eventDatas[0].type).to.equal('saved')
        expect(eventDatas[0].path).to.equal('/users')
        expect(eventDatas[0].data.before).not.exist
        expect(eventDatas[0].data.after.id).to.equal(aUser.id);


        expect(eventDatas[1].type).to.equal('updated')
        expect(eventDatas[1].path).to.equal('/users')
        expect(eventDatas[1].data.before.id).to.equal(aUser.id);
        expect(eventDatas[1].data.after.id).to.equal(aUser.id);

    });


    it('triggerNetworkDeleted', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.networks = [];
        configService.config.gateways = [];
        configService.config.services = [];
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];



        let eventDatas: ConfigEvent[] = [];
        configService.events.on('changed', (data: ConfigEvent) => {
            eventDatas.push(data)
        })

        let network: Network = {
            id: Util.randomNumberString(),
            name: 'default',
            labels: [],
            clientNetwork: '10.10.0.0/16',
            serviceNetwork: '172.16.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        let gateway: Gateway = {
            id: Util.randomNumberString(),
            name: 'myserver',
            labels: [],
            isEnabled: true,
            networkId: network.id,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }
        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],
            host: '1.2.3.4',
            networkId: network.id,
            tcp: 3306,
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }

        await configService.config.services.push(service1);
        await configService.config.gateways.push(gateway);
        await configService.config.networks.push(network);

        let aUser: User = {
            id: Util.randomNumberString(),
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);



        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        let rule: AuthorizationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",

            networkId: network.id,
            userOrgroupIds: [aUser.id],
            serviceId: service1.id,
            profile: { is2FA: true, },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        //add

        configService.config.authorizationPolicy.rules.push(rule);


        let rule2: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'allow',
            networkId: network.id,
            userOrgroupIds: [aUser.id],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }

        //add
        configService.config.authenticationPolicy.rules.push(rule2);

        await configService.deleteNetwork(network.id);

        expect(configService.config.authorizationPolicy.rules.find(x => x.networkId == network.id)).to.not.exist;
        expect(configService.config.authenticationPolicy.rules.find(x => x.networkId == network.id)).to.not.exist;
        expect(configService.config.services.find(x => x.networkId == network.id)).not.exist;
        expect(configService.config.gateways.find(x => x.networkId == network.id)).not.exist;
        expect(configService.config.gateways[0].networkId).to.be.equal('');

        expect(eventDatas.length).to.equal(7);
        expect(eventDatas[0].type).to.equal('updated')
        expect(eventDatas[0].path).to.equal('/gateways')
        expect(eventDatas[0].data.before.id).exist;
        expect(eventDatas[0].data.before.id).exist;

        expect(eventDatas[1].type).to.equal('deleted')
        expect(eventDatas[1].path).to.equal('/services');
        expect(eventDatas[1].data.before.id).exist;
        expect(eventDatas[1].data.after).not.exist;

        expect(eventDatas[2].type).to.equal('deleted')
        expect(eventDatas[2].path).to.equal('/authorizationPolicy/rules');
        expect(eventDatas[2].data.before.id).exist;
        expect(eventDatas[2].data.after).not.exist;

        expect(eventDatas[3].type).to.equal('updated')
        expect(eventDatas[3].path).to.equal('/authorizationPolicy');
        expect(eventDatas[3].data).not.exist;



        expect(eventDatas[4].type).to.equal('deleted')
        expect(eventDatas[4].path).to.equal('/authenticationPolicy/rules');
        expect(eventDatas[4].data.before.id).exist;
        expect(eventDatas[4].data.after).not.exist;

        expect(eventDatas[5].type).to.equal('updated')
        expect(eventDatas[5].path).to.equal('/authenticationPolicy');
        expect(eventDatas[5].data).not.exist;


        expect(eventDatas[6].type).to.equal('deleted')
        expect(eventDatas[6].path).to.equal('/networks');
        expect(eventDatas[6].data.before.id).exist;
        expect(eventDatas[6].data.after).not.exist;





    });

    it('triggerGatewayDeleted', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.networks = [];
        configService.config.gateways = [];
        configService.config.services = [];
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];



        let eventDatas: ConfigEvent[] = [];



        let gateway: Gateway = {
            id: Util.randomNumberString(),
            name: 'myserver',
            labels: [],
            isEnabled: true,
            networkId: 'adaf',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }

        await configService.saveGateway(gateway);
        configService.events.on('changed', (data: ConfigEvent) => {
            eventDatas.push(data)
        })
        await configService.deleteGateway(gateway.id);



        expect(eventDatas.length).to.equal(1);
        expect(eventDatas[0].type).to.equal('deleted')
        expect(eventDatas[0].path).to.equal('/gateways')
        expect(eventDatas[0].data.before.id).exist;
        expect(eventDatas[0].data.after).not.exist;


    });



    it('triggerGroupDeleted', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let eventDatas: ConfigEvent[] = [];
        configService.events.on('changed', (data: ConfigEvent) => {
            eventDatas.push(data)
        })

        let aGroup: Group = {
            id: Util.randomNumberString(),
            name: 'notrh',
            isEnabled: true,
            labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }

        let aUser: User = {
            id: Util.randomNumberString(),
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [aGroup.id],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };
        configService.config.groups.push(aGroup);
        configService.config.users.push(aUser);

        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        let rule: AuthorizationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",

            networkId: 'networkId',
            userOrgroupIds: [aGroup.id],
            serviceId: 'some service',
            profile: { is2FA: true, },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        //add

        configService.config.authorizationPolicy.rules.push(rule);


        let rule2: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: [aGroup.id],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }

        //add
        configService.config.authenticationPolicy.rules.push(rule2);

        await configService.deleteGroup(aGroup.id);
        expect(configService.config.authorizationPolicy.rules.find(x => x.userOrgroupIds.includes(aGroup.id))).to.not.exist;
        expect(configService.config.authenticationPolicy.rules.find(x => x.userOrgroupIds.includes(aUser.id))).to.not.exist;

        expect(eventDatas.length).to.equal(6);

        expect(eventDatas[1].type).to.equal('updated')
        expect(eventDatas[1].path).to.equal('/authenticationPolicy/rules');
        expect(eventDatas[1].data.before.id).exist;
        expect(eventDatas[1].data.after.id).exist;

        expect(eventDatas[2].type).to.equal('updated')
        expect(eventDatas[2].path).to.equal('/authenticationPolicy');
        expect(eventDatas[2].data).not.exist;

        expect(eventDatas[3].type).to.equal('updated')
        expect(eventDatas[3].path).to.equal('/authorizationPolicy/rules');
        expect(eventDatas[3].data.before.id).exist;
        expect(eventDatas[3].data.after.id).exist;

        expect(eventDatas[4].type).to.equal('updated')
        expect(eventDatas[4].path).to.equal('/authorizationPolicy');
        expect(eventDatas[4].data).not.exist;


        expect(eventDatas[5].type).to.equal('deleted');
        expect(eventDatas[5].path).to.equal('/groups');
        expect(eventDatas[5].data.before.id).exist;
        expect(eventDatas[5].data.after).not.exist;




    });


    it('triggerServiceDeleted', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.networks = [];
        configService.config.gateways = [];
        configService.config.services = [];
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];



        let eventDatas: ConfigEvent[] = [];
        configService.events.on('changed', (data: ConfigEvent) => {
            eventDatas.push(data)
        })


        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],
            host: '1.2.3.4',
            networkId: 'sadid',
            tcp: 3306,
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }

        await configService.config.services.push(service1);


        let aUser: User = {
            id: Util.randomNumberString(),
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);



        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        let rule: AuthorizationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",

            networkId: 'ssid',
            userOrgroupIds: [aUser.id],
            serviceId: service1.id,
            profile: { is2FA: true, },
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        //add

        configService.config.authorizationPolicy.rules.push(rule);



        await configService.deleteService(service1.id);

        expect(configService.config.authorizationPolicy.rules.find(x => x.serviceId == service1.id)).to.not.exist;


        expect(eventDatas.length).to.equal(3);

        expect(eventDatas[0].type).to.equal('deleted')
        expect(eventDatas[0].path).to.equal('/authorizationPolicy/rules');
        expect(eventDatas[0].data.before.id).exist;
        expect(eventDatas[0].data.after).not.exist;

        expect(eventDatas[1].type).to.equal('updated')
        expect(eventDatas[1].path).to.equal('/authorizationPolicy');
        expect(eventDatas[1].data).not.exist;


        expect(eventDatas[2].type).to.equal('deleted')
        expect(eventDatas[2].path).to.equal('/services');
        expect(eventDatas[2].data.before.id).exist;
        expect(eventDatas[2].data.after).not.exist;





    });








});

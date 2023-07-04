
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { ConfigService } from '../src/service/configService';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Gateway, Network } from '../src/model/network';
import { AuthCommon, BaseOAuth, BaseLocal, AuthLocal, BaseLdap, BaseSaml } from '../src/model/authSettings';
import { Group } from '../src/model/group';
import { Service } from '../src/model/service';
import { AuthenticationRule } from '../src/model/authenticationPolicy';
import { AuthorizationRule } from '../src/model/authorizationPolicy';


import chaiExclude from 'chai-exclude';
import { RedisConfigService } from '../src/service/redisConfigService';
import { RedisService } from '../src/service/redisService';
import { config } from 'process';
import { WatchItem } from '../src/service/watchService';
import { authenticate } from 'passport';
import { SystemLogService } from '../src/service/systemLogService';
import { ConfigWatch } from '../src/model/config';
import IPCIDR from 'ip-cidr';
import * as ipaddr from 'ip-address';
import { calculateCountryId } from '../src/model/country';
import { SSLCertificate, SSLCertificateEx } from '../src/model/cert';
import { DevicePosture } from '../src/model/authenticationProfile';



chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);

function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete a.password;
    delete b.insertDate;
    delete b.updateDate;
    delete b.password;
    expect(a).to.deep.equal(b);
}
function expectCertToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete a.password;
    delete b.insertDate;
    delete b.updateDate;
    delete b.password;
    delete b.privateKey;
    expect(a).to.deep.equal(b);
}

describe('redisConfigService', async () => {
    const redis = new RedisService();
    const redisStream = new RedisService();
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const encKey = 'AuX165Jjz9VpeOMl3msHbNAncvDYezMg'

    const systemLogService = new SystemLogService(redis, redisStream, encKey, 'test');

    beforeEach(async () => {
        await redis.flushAll();
    })

    it('saveConfigToFile', async () => {

    });
    it('loadConfigFromFile', async () => {

    });

    it('rSave', async () => {
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        await configService.rSave('users', undefined, { id: 1 });
        const data = await redis.get('/config/users/1', false);
        expect(data).exist;

    });

    it('rGet', async () => {
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        await configService.rSave('users', undefined, { id: 1 });
        const data = await configService.rGetWith<User>('users', '1')
        expect(data).exist;

        expect(data?.id).to.equal(1);

    });
    it('rExits', async () => {
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        await configService.rSave('users', undefined, { id: 1 });
        const data = await configService.rExists('users/1')
        expect(data).to.be.true;

    });


    it('rDel', async () => {
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        let logs: ConfigWatch<User>[] = [];
        configService.logWatcher.watcher.events.on('data', (data: WatchItem<ConfigWatch<User>>) => {
            logs.push(data.val);
        })
        //await configService.logWatcher.read();
        await configService.rSave('users', undefined, { id: 1 });
        await configService.rDel('users', { id: 1 });
        const data = await configService.rExists('users/1')
        expect(data).to.be.false;
        await Util.sleep(1000);
        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();
        await Util.sleep(1000);
        expect(logs.length).to.equal(2);
        expect(logs[0].type).to.equal('put');
        expect(logs[1].type).to.equal('del');

    }).timeout(120000);

    it('rSaveArray', async () => {
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        await configService.rSaveArray('users', [{ id: 1 }, { id: 2 }]);
        const data = await configService.rExists('users/1')
        expect(data).to.be.true;
        const data2 = await configService.rExists('users/2')
        expect(data2).to.be.true;

    });
    it('rGetAll', async () => {
        let configService = new RedisConfigService(redis, redisStream,
            systemLogService, encKey, filename);

        await configService.rSaveArray('users', [{ id: 1 }, { id: 2 }]);
        const data = await configService.rGetAll<User>('users')
        expect(data.length).to.be.equal(2);

        expect(data[0].id).exist;
    });


    it('saveV1', async () => {
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        await configService.saveV1();
        const users = await configService.rGetAll('users')
        expect(users.length).to.be.equal(1); // we are adding some users for test

        const networks = await configService.rGetAll('networks');
        expect(networks.length).to.equal(1);
        //check index
        const id = await configService.rGetIndex('users/username', 'admin');
        expect(id).exist;
    }).timeout(60000);


    it('init', async () => {
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        await configService.init();
        const users = await configService.rGetAll('users')
        expect(users.length).to.be.equal(1); // we are adding some users for test

    }).timeout(60000);

    it('getUserByUsername', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        const aUserDb = await configService.getUserByUsername(aUser.username);
        expect(aUserDb).exist;
        expectToDeepEqual(aUserDb, aUser);

    });

    it('getUserByUsernameAndSource', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        const aUserDb = await configService.getUserByUsernameAndSource(aUser.username, 'local');
        expect(aUserDb).exist;
        expectToDeepEqual(aUserDb, aUser);


    });

    /*  it('getUserByApiKey', async () => {
 
         //first create a config and save to a redis
         let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
         configService.config.users = [];
         let aUser: User = {
             id: '6hiryy8ujv3n',
             username: 'hamza.kilic@ferrumgate.com',
             name: 'test', source: 'local',
             password: 'passwordWithHash', groupIds: [],
             apiKey: { key: '1fviqq286bmcm' },
             insertDate: new Date().toISOString(),
             updateDate: new Date().toISOString()
         };
 
         configService.config.users.push(aUser);
         await configService.init();
         const userDb = await configService.getUserByApiKey('1fviqq286bmcm');
         expect(userDb?.id).to.equal('6hiryy8ujv3n');
 
     });
  */
    it('getUserById', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        const user = await configService.getUserById('someid');
        expectToDeepEqual(user, aUser);

    });




    it('getUsersBy', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        const usersCount = await configService.getUserCount();
        expect(usersCount).to.equal(4);
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
        const list9 = await configService.getUsersBy(0, 0, '', [], [], [], [], true);
        expect(list9.items.length).to.be.equal(1);

        //search by isVerified
        const list10 = await configService.getUsersBy(0, 0, '', [], [], [], [], undefined, true);
        expect(list10.items.length).to.be.equal(1);

        //search by isLocked
        const list11 = await configService.getUsersBy(0, 0, '', [], [], [], [], undefined, undefined, true);
        expect(list11.items.length).to.be.equal(1);

        //search by isEmailVerified
        const list12 = await configService.getUsersBy(0, 0, '', [], [], [], [], undefined, undefined, undefined, true);
        expect(list12.items.length).to.be.equal(1);


    });

    it('getUserByRoleIds', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        const users = await configService.getUserByRoleIds(['Admin']);

        expect(users.length).to.be.equal(1);

        const users2 = await configService.getUserByRoleIds(['User']);

        expect(users2.length).to.be.equal(0);

    });

    it('getUserByUsernameAndPass', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        const user = await configService.getUserByUsernameAndPass('hamza.kilic@ferrumgate.com', 'passwordWithHash');
        delete aUser.password;
        expect(user).to.deep.include(aUser);

        const user2 = await configService.getUserByUsernameAndPass('hamza.kilic@ferrumgate.com', 'passwordWithHash2');

        expect(user2).to.be.undefined;

    });

    it('getUserByUsername', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        const user = await configService.getUserByUsername('hamza.kilic@ferrumgate.com');
        delete aUser.password;
        expect(user).to.deep.include(aUser);

    });

    it('getUserByIdAndPass', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        const user = await configService.getUserByIdAndPass('someid', 'passwordWithHash');
        delete aUser.password;
        expect(user).to.deep.include(aUser);

    });

    it('saveUser', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        let fakeUser = {
            ...aUser
        }
        fakeUser.id = 'test';
        await configService.saveUser(fakeUser);
        const userDb = await configService.getUserByUsername('hamza.kilic@ferrumgate.com');
        expect(userDb?.id).to.equal('someid');

    });

    it('deleteUser', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        let fakeUser = {
            ...aUser
        }
        fakeUser.id = 'test';
        await configService.saveUser(fakeUser);
        await configService.deleteUser(fakeUser.id);
        const userDb = await configService.getUserById(fakeUser.id)
        expect(userDb).not.exist;

        await configService.deleteUser(aUser.id);
        const userDb2 = await configService.getUserById(aUser.id)
        expect(userDb2).not.exist;

    });

    it('changeAdminUser', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.users = [];
        let aUser: User = {
            id: 'someid',
            username: 'admin',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        await configService.init();

        await configService.changeAdminUser('test@ferrumgate', 'test');
        const userDb = await configService.getUserByUsername('admin')
        expect(userDb).not.exist;

        const userDb2 = await configService.getUserByUsername('test@ferrumgate');
        expect(userDb2).exist;

    });


    it('setCaptcha/getCaptcha', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.captcha = {};
        await configService.init();

        await configService.setCaptcha({ client: 'x', server: 'y' });
        const db = await configService.getCaptcha()
        expect(db.client).to.equal('x');


    });

    it('setJWTSSLCertificate/getJWTSSLCertificate', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.jwtSSLCertificate = {
            idEx: Util.randomNumberString(),
            name: 'JWT',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            labels: [], isEnabled: true, usages: []
        };
        await configService.init();

        await configService.setJWTSSLCertificate({ privateKey: 'a' });
        const db = await configService.getJWTSSLCertificateSensitive()
        expect(db.privateKey).to.equal('a');

        const db2 = await configService.getJWTSSLCertificate()
        expect(db2.privateKey).not.exist;


    });

    it('setWebSSLCertificate/getWebSSLCertificate', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.webSSLCertificate = {
            idEx: Util.randomNumberString(),
            name: 'Web',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            labels: [], isEnabled: true, usages: []
        };
        await configService.init();

        await configService.setWebSSLCertificate({ privateKey: 'a' });
        const db = await configService.getWebSSLCertificateSensitive()
        expect(db.privateKey).to.equal('a');

        const db2 = await configService.getWebSSLCertificate()
        expect(db2.privateKey).not.exist;


    });

    it('setCASSLCertificate/getCASSLCertificate', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.caSSLCertificate = {
            idEx: Util.randomNumberString(),
            name: 'CA',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            labels: [], isEnabled: true, usages: []
        };
        await configService.init();

        await configService.setCASSLCertificate({ privateKey: 'b', publicCrt: 'c' });
        const db = await configService.getCASSLCertificateSensitive()
        expect(db.privateKey).to.equal('b');

        const db2 = await configService.getCASSLCertificate()
        expect(db2.privateKey).not.exist;



    }).timeout(60000);

    it('setLogo/getLogo', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.logo = {};
        await configService.init();

        await configService.setLogo({ default: 'a' });
        const db = await configService.getLogo()
        expect(db.default).to.equal('a');


    });




    it('authSettingsCommon', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
        let common: AuthCommon = {
            bla: 'test'
        }
        await configService.setAuthSettingCommon(common);
        const returned = await configService.getAuthSettingCommon() as any;
        expect(returned).to.be.exist;
        expect(returned.bla).exist;

    });

    it('authSettingsOAuth', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.auth = {
            common: {}, local: {} as any, saml: { providers: [] } as any, ldap: { providers: [] } as any, oauth: { providers: [] } as any
        }
        await configService.init();
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
        expectToDeepEqual(returned.providers[0], oauth);
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


    }).timeout(60000);

    it('setAuthSettingLocal/getAuthSettingLocal', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.auth = {
            common: {}, local: {} as any, saml: { providers: [] } as any, ldap: { providers: [] } as any, oauth: { providers: [] } as any
        }
        await configService.init();
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
        await configService.setAuthSettingLocal(local);

        const returned = await configService.getAuthSettingLocal();
        expectToDeepEqual(returned, local);


    });


    it('authSettingsLdap', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.auth = {
            common: {}, local: {} as any, saml: { providers: [] } as any, ldap: { providers: [] } as any, oauth: { providers: [] } as any
        }
        await configService.init();
        let ldap: BaseLdap = {
            name: 'google',
            baseType: 'oauth',
            type: 'google',
            id: 'oneid',

            tags: [],
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            groupnameField: '', host: 'adfa',
            searchBase: 'adfa', usernameField: 'adfa'
        }

        //add
        await configService.addAuthSettingLdap(ldap);

        const returned = await configService.getAuthSettingLdap();
        expectToDeepEqual(returned.providers[0], ldap);
        //delete
        await configService.deleteAuthSettingLdap(ldap.id);
        const returned2 = await configService.getAuthSettingOAuth();
        expect(returned2.providers.length).to.equal(0);
        // adding same id
        await configService.addAuthSettingLdap(ldap);
        const cloned = Util.clone(ldap);
        await configService.addAuthSettingLdap(ldap);
        const returned3 = await configService.getAuthSettingLdap();
        expect(returned3.providers.length).to.equal(1);


    });

    it('authSettingsSaml', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.auth = {
            common: {}, local: {} as any, saml: { providers: [] } as any, ldap: { providers: [] } as any, oauth: { providers: [] } as any
        }
        await configService.init();
        let saml: BaseSaml = {
            name: 'google',
            baseType: 'oauth',
            type: 'google',
            id: 'oneid',

            tags: [],
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            cert: '', issuer: '', loginUrl: '', nameField: '', usernameField: ''
        }

        //add
        await configService.addAuthSettingSaml(saml);

        const returned = await configService.getAuthSettingSaml();
        expectToDeepEqual(returned.providers[0], saml);
        //delete
        await configService.deleteAuthSettingSaml(saml.id);
        const returned2 = await configService.getAuthSettingSaml();
        expect(returned2.providers.length).to.equal(0);
        // adding same id
        await configService.addAuthSettingSaml(saml);
        const cloned = Util.clone(saml);
        await configService.addAuthSettingSaml(saml);
        const returned3 = await configService.getAuthSettingSaml();
        expect(returned3.providers.length).to.equal(1);


    });

    it('saveNetwork getNetwork getNetworkByName', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
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
        expectToDeepEqual(networkDb, network);
        const networkDb2 = await configService.getNetworkByName('default2');
        expectToDeepEqual(networkDb2, network);

    });

    it('getNetworkByHostname', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
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
        expectToDeepEqual(networkDb, network);

    });


    it('deleteNetwork', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
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

    it('getGateway/saveGateway', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
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
        expectToDeepEqual(gatewayDb, gateway);

    });
    it('deleteGateway', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
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

    it('getDomain/setDomain', async () => {
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        await configService.init();

        await configService.setDomain('test.me');
        const domain = await configService.getDomain();
        expect(domain).to.equal('test.me');

    }).timeout(10000);


    it('getUrl/setUrl', async () => {
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        await configService.init();

        await configService.setUrl('test.url');
        const url = await configService.getUrl();
        expect(url).to.equal('test.url');

    }).timeout(10000);

    it('getIsConfigured/setIsConfigured', async () => {
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        await configService.init();

        await configService.setIsConfigured(1);
        const val = await configService.getIsConfigured();
        expect(val).to.equal(1);

    }).timeout(10000);

    it('getGroup', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
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

        expectToDeepEqual(returned, group);


    });

    it('getGroupBySearch', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.groups = [];
        await configService.init();
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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.groups = [];
        await configService.init();
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


    });

    it('saveGroup', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.groups = [];
        await configService.init();
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

        expectToDeepEqual(returned, group);

    });

    it('deleteGroup', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);


        configService.config.groups = [];
        configService.config.users = [];
        await configService.init();
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
        await configService.saveUser(aUser);

        await configService.deleteGroup(group.id);

        const returned = await configService.getGroup(group.id)

        expect(returned).not.exist;
        const user = await configService.getUserById(aUser.id)
        expect(user?.groupIds.length).to.equal(0);

    });

    ///// service 

    it('getService', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.services = [];
        await configService.init();
        let service: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],

            hosts: [{ host: '1.2.3.4' }],
            ports: [{ port: 3306, isTcp: true }],
            networkId: 'abcd',

            assignedIp: '1.3',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service);

        const returned = await configService.getService(service.id);

        expectToDeepEqual(returned, service);


    });

    it('getServicesBy', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.services = [];
        await configService.init();
        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],

            hosts: [{ host: '1.2.3.4' }],
            networkId: 'abcd',

            ports: [{ port: 3306, isTcp: true }],
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

            hosts: [{ host: '192.168.10.10' }],
            networkId: 'abcd',

            ports: [{ port: 3306, isTcp: true }],
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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.services = [];
        await configService.init();
        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],

            hosts: [{ host: '1.2.3.4' }],
            networkId: 'abcd',

            ports: [{ port: 3306, isTcp: true }],
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

            hosts: [{ host: '192.168.10.10' }],
            networkId: 'dabc',

            ports: [{ port: 3306, isTcp: true }],
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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.services = [];
        await configService.init();
        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],

            hosts: [{ host: '1.2.3.4' }],
            networkId: 'abcd',

            ports: [{ port: 3306, isTcp: true }],
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

            hosts: [{ host: '192.168.10.10' }],
            networkId: 'abcd',

            ports: [{ port: 3306, isTcp: true }],
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }
        //add
        await configService.saveService(service2);

        const returned = await configService.getServicesBy();
        expect(returned.length).to.be.equal(2);

        expectToDeepEqual(returned[0], service1);

    });

    it('saveService', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.services = [];
        await configService.init();
        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],

            hosts: [{ host: '1.2.3.4' }],
            networkId: 'abcd',

            ports: [{ port: 3306, isTcp: true }],
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

        expectToDeepEqual(returned, service1);

    });

    it('deleteService', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.groups = [];
        await configService.init();

        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],

            hosts: [{ host: '1.2.3.4' }],
            networkId: 'abcd',

            ports: [{ port: 3306, isTcp: true }],
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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.authenticationPolicy.rules = [];
        await configService.init();
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        //add
        await configService.saveAuthenticationPolicyRule(rule);

        const policy = await configService.getAuthenticationPolicy();
        expect(policy.rules.find(x => x.id == rule.id)).to.exist;


    });
    it('getAuthenticationPolicy', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.authenticationPolicy.rules = [];
        await configService.init();
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        configService.config.authenticationPolicy.rules.push(rule);
        await configService.saveAuthenticationPolicyRule(rule);

        const policy = await configService.getAuthenticationPolicy();
        expect(policy.rules.find(x => x.id == rule.id)).to.exist;
        expect(policy.rules.length).to.equal(1);

    });

    it('getAuthenticationPolicyUnsafe', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.authenticationPolicy.rules = [];
        await configService.init();
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        configService.config.authenticationPolicy.rules.push(rule);
        await configService.saveAuthenticationPolicyRule(rule);

        const policy = await configService.getAuthenticationPolicy();
        expect(policy.rules.find(x => x.id == rule.id)).to.exist;
        expect(policy.rules.length).to.equal(1);

    });

    it('deleteAuthenticationPolicyRule', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.authenticationPolicy.rules = [];
        await configService.init();
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
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
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, filename);
        configService.config.authenticationPolicy.rules = [];
        configService.config.authenticationPolicy.rulesOrder = [];
        await configService.init();
        let rule1: AuthenticationRule = {
            id: '1',
            name: "zero trust1",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }


        let rule2: AuthenticationRule = {
            id: '2',
            name: "zero trust2",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }



        let rule3: AuthenticationRule = {
            id: '3',
            name: "zero trust3",
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        await configService.saveAuthenticationPolicyRule(rule3);
        await configService.saveAuthenticationPolicyRule(rule2);
        await configService.saveAuthenticationPolicyRule(rule1);

        let policy = await configService.getAuthenticationPolicy();
        expect(policy.rulesOrder[0]).to.be.equal(rule1.id);
        expect(policy.rulesOrder[1]).to.be.equal(rule2.id);
        expect(policy.rulesOrder[2]).to.be.equal(rule3.id);



        await configService.updateAuthenticationRulePos(rule1.id, 0, rule3.id, 2);
        policy = await configService.getAuthenticationPolicy();
        expect(policy.rulesOrder[0]).to.be.equal('2');
        expect(policy.rulesOrder[1]).to.be.equal('3');
        expect(policy.rulesOrder[2]).to.be.equal('1');

        await configService.updateAuthenticationRulePos(rule1.id, 2, rule3.id, 1);
        policy = await configService.getAuthenticationPolicy();
        expect(policy.rulesOrder[0]).to.be.equal('2');
        expect(policy.rulesOrder[1]).to.be.equal('1');
        expect(policy.rulesOrder[2]).to.be.equal('3');

        await configService.updateAuthenticationRulePos(rule1.id, 1, rule2.id, 0);
        policy = await configService.getAuthenticationPolicy();

        expect(policy.rulesOrder[0]).to.be.equal('1');
        expect(policy.rulesOrder[1]).to.be.equal('2');
        expect(policy.rulesOrder[2]).to.be.equal('3');

        let errrored = false;
        try {
            await configService.updateAuthenticationRulePos(rule1.id, 1, rule1.id, 5);
        } catch (err) {
            errrored = true;
        }
        expect(errrored).to.be.true;





    });



    //authorizationPolicy

    it('saveAuthorizationPolicyAddRule', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.authorizationPolicy.rules = [];
        await configService.init();
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

        const policy = await configService.getAuthorizationPolicy();
        expect(policy.rules.find(x => x.id == rule.id)).to.exist;


    });
    it('getAuthorizationPolicy', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        await configService.init();
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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.authorizationPolicy.rules = [];
        await configService.init();
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

    it('deleteAuthorizationPolicyRule', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.authorizationPolicy.rules = [];
        await configService.init();
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


    it('updateAuthorizationRulePos', async () => {

        //first create a config and save to a file
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, filename);
        configService.config.authorizationPolicy.rules = [];
        configService.config.authorizationPolicy.rulesOrder = [];
        await configService.init();
        let rule1: AuthorizationRule = {
            id: '1',
            name: "zero trust1",
            serviceId: '12',
            profile: { is2FA: true },
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }


        let rule2: AuthorizationRule = {
            id: '2',
            name: "zero trust2",
            serviceId: '12',
            profile: { is2FA: true },
            networkId: 'networkId',

            userOrgroupIds: ['somegroupid'],

            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }


        let rule3: AuthorizationRule = {
            id: '3',
            name: "zero trust3",

            serviceId: '12',
            profile: { is2FA: true },
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],

            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }
        await configService.saveAuthorizationPolicyRule(rule3);
        await configService.saveAuthorizationPolicyRule(rule2);
        await configService.saveAuthorizationPolicyRule(rule1);


        let policy = await configService.getAuthorizationPolicy();




        expect(policy.rulesOrder[0]).to.be.equal(rule1.id);
        expect(policy.rulesOrder[1]).to.be.equal(rule2.id);
        expect(policy.rulesOrder[2]).to.be.equal(rule3.id);



        await configService.updateAuthorizationRulePos(rule1.id, 0, rule3.id, 2);
        policy = await configService.getAuthorizationPolicy();
        expect(policy.rulesOrder[0]).to.be.equal('2');
        expect(policy.rulesOrder[1]).to.be.equal('3');
        expect(policy.rulesOrder[2]).to.be.equal('1');

        await configService.updateAuthorizationRulePos(rule1.id, 2, rule3.id, 1);
        policy = await configService.getAuthorizationPolicy();

        expect(policy.rulesOrder[0]).to.be.equal('2');
        expect(policy.rulesOrder[1]).to.be.equal('1');
        expect(policy.rulesOrder[2]).to.be.equal('3');

        await configService.updateAuthorizationRulePos(rule1.id, 1, rule2.id, 0);
        policy = await configService.getAuthorizationPolicy();

        expect(policy.rulesOrder[0]).to.be.equal('1');
        expect(policy.rulesOrder[1]).to.be.equal('2');
        expect(policy.rulesOrder[2]).to.be.equal('3');

        let errrored = false;
        try {
            await configService.updateAuthorizationRulePos(rule1.id, 1, rule1.id, 5);
        } catch (err) {
            errrored = true;
        }
        expect(errrored).to.be.true;





    });



    it('triggerUserDeleted', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.users = [];
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        configService.config.groups = [];
        configService.config.networks = [];
        configService.config.gateways = [];

        let logs: any[] = [];

        await configService.init();
        await configService.logWatcher.watcher.trim(1);
        configService.logWatcher.watcher.events.on('data', (data: any) => {

            logs.push(data);
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
        await configService.saveUser(aUser);

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
        await configService.saveAuthorizationPolicyRule(rule);

        let rule2: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: [aUser.id],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }

        //add
        configService.config.authenticationPolicy.rules.push(rule2);
        await configService.saveAuthenticationPolicyRule(rule2);

        await configService.deleteUser(aUser.id);
        const users = await configService.getUserByUsername(aUser.username);
        const authenticationPolicy = await configService.getAuthenticationPolicy();
        const authorizationPolicy = await configService.getAuthorizationPolicy();
        expect(authorizationPolicy.rules.find(x => x.userOrgroupIds.includes(aUser.id))).to.not.exist;
        expect(authenticationPolicy.rules.find(x => x.userOrgroupIds.includes(aUser.id))).to.not.exist;
        expect(authorizationPolicy.rules.length).to.equal(0);
        expect(authenticationPolicy.rules.length).to.equal(0);

        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();


        expect(logs.length > 0).to.be.true;




    }).timeout(60000);


    it('triggerUserSavedOrUpdated', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.users = [];
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        configService.config.groups = [];
        configService.config.networks = [];
        configService.config.gateways = [];

        let logs: any[] = [];

        await configService.init();
        await configService.logWatcher.watcher.trim(1);
        configService.logWatcher.watcher.events.on('data', (data: any) => {

            logs.push(data);
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
        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();

        expect(logs.length > 0).to.be.true;

    }).timeout(60000);


    it('triggerNetworkDeleted', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.users = [];
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        configService.config.groups = [];
        configService.config.networks = [];
        configService.config.gateways = [];

        let logs: any[] = [];

        await configService.init();
        await configService.logWatcher.watcher.trim(1);
        configService.logWatcher.watcher.events.on('data', (data: any) => {

            logs.push(data);
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

            hosts: [{ host: '1.2.3.4' }],
            networkId: network.id,

            ports: [{ port: 3306, isTcp: true }],
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }

        await configService.saveService(service1);
        await configService.saveGateway(gateway);
        await configService.saveNetwork(network);

        let aUser: User = {
            id: Util.randomNumberString(),
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.saveUser(aUser);



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
        await configService.saveAuthorizationPolicyRule(rule);


        let rule2: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: network.id,
            userOrgroupIds: [aUser.id],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }

        //add
        configService.config.authenticationPolicy.rules.push(rule2);
        await configService.saveAuthenticationPolicyRule(rule2);

        await configService.deleteNetwork(network.id);
        const authorizationPolicy = await configService.getAuthorizationPolicy();
        const authenticationPolicy = await configService.getAuthenticationPolicy();
        const services = await configService.getServicesAll();
        const gateways = await configService.getGatewaysAll();


        expect(authorizationPolicy.rules.find(x => x.networkId == network.id)).to.not.exist;
        expect(authenticationPolicy.rules.find(x => x.networkId == network.id)).to.not.exist;
        expect(services.find(x => x.networkId == network.id)).not.exist;
        expect(gateways.find(x => x.networkId == network.id)).not.exist;
        expect(gateways[0].networkId).to.be.equal('');

        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();

        expect(logs.length > 0).to.be.true;

    }).timeout(60000);

    it('triggerGatewayDeleted', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.users = [];
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        configService.config.groups = [];
        configService.config.networks = [];
        configService.config.gateways = [];

        let logs: any[] = [];

        await configService.init();
        await configService.logWatcher.watcher.trim(1);
        configService.logWatcher.watcher.events.on('data', (data: any) => {

            logs.push(data);
        })


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

        await configService.deleteGateway(gateway.id);

        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();
        expect(logs.length > 0).to.be.true;


    }).timeout(60000);



    it('triggerGroupDeleted', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.users = [];
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        configService.config.groups = [];
        configService.config.networks = [];
        configService.config.gateways = [];

        let logs: any[] = [];

        await configService.init();
        await configService.logWatcher.watcher.trim(1);
        configService.logWatcher.watcher.events.on('data', (data: any) => {

            logs.push(data);
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
        await configService.saveGroup(aGroup);
        configService.config.users.push(aUser);
        await configService.saveUser(aUser);

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
        await configService.saveAuthorizationPolicyRule(rule);


        let rule2: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: 'networkId',
            userOrgroupIds: [aGroup.id],
            profile: {},
            isEnabled: true,
            updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString()

        }

        //add
        configService.config.authenticationPolicy.rules.push(rule2);
        await configService.saveAuthenticationPolicyRule(rule2);

        await configService.deleteGroup(aGroup.id);
        const authorizationPolicy = await configService.getAuthorizationPolicy();
        const authenticationPolicy = await configService.getAuthenticationPolicy();
        expect(authorizationPolicy.rules.find(x => x.userOrgroupIds.includes(aGroup.id))).to.not.exist;
        expect(authenticationPolicy.rules.find(x => x.userOrgroupIds.includes(aUser.id))).to.not.exist;
        expect(authorizationPolicy.rules.length).to.equal(0);
        expect(authenticationPolicy.rules.length).to.equal(0);

        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();

        expect(logs.length > 0).to.be.true;


    }).timeout(60000);


    it('triggerServiceDeleted', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.users = [];
        configService.config.authenticationPolicy.rules = [];
        configService.config.authorizationPolicy.rules = [];
        configService.config.groups = [];
        configService.config.networks = [];
        configService.config.gateways = [];

        let logs: any[] = [];

        await configService.init();
        await configService.logWatcher.watcher.trim(1);
        configService.logWatcher.watcher.events.on('data', (data: any) => {

            logs.push(data);
        })


        let service1: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],

            hosts: [{ host: '1.2.3.4' }],
            networkId: 'sadid',

            ports: [{ port: 3306, isTcp: true }],
            assignedIp: '10.0.0.1',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            count: 1

        }

        await configService.config.services.push(service1);
        await configService.saveService(service1);


        let aUser: User = {
            id: Util.randomNumberString(),
            username: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        await configService.saveUser(aUser);



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
        await configService.saveAuthorizationPolicyRule(rule);


        await configService.deleteService(service1.id);

        const authorizationPolicy = await configService.getAuthorizationPolicy();
        expect(authorizationPolicy.rules.find(x => x.serviceId == service1.id)).to.not.exist;

        await configService.logWatcher.watcher.read();
        await configService.logWatcher.watcher.read();

        expect(logs.length > 0).to.be.true;


    }).timeout(60000);



    it('saveConfigToString', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        const str = await configService.saveConfigToString()

        expect(str).exist

    });


    it('getES/setES', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.captcha = {};
        await configService.init();

        await configService.setES({ host: 'abc', user: 'adfa' });
        const db = await configService.getES()
        expect(db?.host).to.equal('abc');


    });


    it('getAll', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
        await configService.setCaptcha({ client: '2', server: '3' });

        let config = configService.createConfig();
        await configService.getConfig(config);
        expect(config.captcha.client).to.equal('2');
        expect(config.captcha.server).to.equal('3');


    });

    it('setAll', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
        await configService.setCaptcha({ client: '2', server: '3' });

        const catpcha1 = await configService.getCaptcha();
        expect(catpcha1.client).to.equal('2');
        expect(catpcha1.server).to.equal('3');

        let config = configService.createConfig();
        config.captcha = { client: '4', server: '5' };
        await configService.setConfig(config);
        const catpcha = await configService.getCaptcha();
        expect(catpcha.client).to.equal('4');
        expect(catpcha.server).to.equal('5');


    });


    it('getIpIntelligenceSources/saveIpIntelligenceSource/deleteIpIntelligenceSource', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.ipIntelligence.sources = [];
        await configService.init();

        const source = await configService.getIpIntelligenceSources();
        expect(source.length).to.equal(0);

        const item = { name: 'test', type: 'test2', id: Util.randomNumberString(), insertDate: '', updateDate: '' };
        await configService.saveIpIntelligenceSource(item);

        const source2 = await configService.getIpIntelligenceSources();
        expect(source2.length).to.equal(1);

        await configService.deleteIpIntelligenceSource(item.id);
        const source3 = await configService.getIpIntelligenceSources();
        expect(source3.length).to.equal(0);


    });

    it('getIpIntelligenceList/saveIpIntelligenceList/deleteIpIntelligenceList', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.ipIntelligence.sources = [];
        await configService.init();

        const lists = await configService.getIpIntelligenceLists();
        expect(lists.length).to.equal(0);

        const item = { name: 'test', type: 'test2', id: Util.randomNumberString(), insertDate: '', updateDate: '' };
        await configService.saveIpIntelligenceList(item);

        const source2 = await configService.getIpIntelligenceLists();
        expect(source2.length).to.equal(1);

        const source3 = await configService.getIpIntelligenceList(source2[0].id);
        expect(source3).exist;

        await configService.deleteIpIntelligenceSource(item.id);
        const source4 = await configService.getIpIntelligenceSources();
        expect(source4.length).to.equal(0);


    });


    it('getInSSLCertificate', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
        configService.config.inSSLCertificates = [];
        let crt: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'north',
            labels: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isEnabled: true, usages: []



        }
        //add
        await configService.saveInSSLCertificate(crt);

        const returned = await configService.getInSSLCertificateSensitive(crt.id);

        expectToDeepEqual(returned, crt);

        const returned2 = await configService.getInSSLCertificate(crt.id);
        expect(returned2).exist;
        expect(returned2?.privateKey).not.exist;



    });




    it('getInSSLCertificateAll', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.inSSLCertificates = [];
        await configService.init();
        let crt: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'north',

            labels: ['test2'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            privateKey: 'adsfa', publicCrt: 'adfafda',
            isEnabled: true, usages: []

        }
        //add
        await configService.saveInSSLCertificate(crt);

        let crt2: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'south',

            labels: ['test'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            privateKey: 'adfafa', publicCrt: 'adsfasfa',
            isEnabled: true, usages: []

        }
        //add
        await configService.saveInSSLCertificate(crt2);

        const returned = await configService.getInSSLCertificateAll();
        expect(returned.length).to.be.equal(4);//one more from default web intermediate


    });

    it('saveInSSLCertificate', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.inSSLCertificates = [];
        await configService.init();
        let crt: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'north',

            labels: ['test2'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            privateKey: 'asdfa', publicCrt: 'asdfasfa',
            isEnabled: true,
            usages: []

        }
        //add
        await configService.saveInSSLCertificate(crt);

        crt.name = 'north2';
        //add
        await configService.saveInSSLCertificate(crt);

        const returned = await configService.getInSSLCertificateSensitive(crt.id)

        expectToDeepEqual(returned, crt);

    });

    it('deleteInSSLCertificate', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);


        configService.config.inSSLCertificates = [];

        await configService.init();
        let crt: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'north',

            labels: ['test2'],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            privateKey: 'adfa', publicCrt: 'asdfasdfsa',
            isEnabled: true, usages: []


        }
        //add
        await configService.saveInSSLCertificate(crt);


        await configService.deleteInSSLCertificate(crt.id);

        const returned = await configService.getInSSLCertificate(crt.id)

        expect(returned).not.exist;



    });

    //// device posture

    it('getDevicePosture', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
        configService.config.groups = [];
        let posture: DevicePosture = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: [],
            os: 'android',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveDevicePosture(posture);

        const returned = await configService.getDevicePosture(posture.id);

        expectToDeepEqual(returned, posture);


    });

    it('getDevicePostureBySearch', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.devicePostures = [];
        await configService.init();
        let posture: DevicePosture = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2'],
            os: 'android',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveDevicePosture(posture);

        let posture2: DevicePosture = {
            id: Util.randomNumberString(),
            name: 'south',
            isEnabled: true,
            labels: ['test'],
            os: 'linux',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveDevicePosture(posture2);

        const returned = await configService.getDevicePosturesBySearch('test');
        expect(returned.length).to.equal(2);

        const returned2 = await configService.getDevicePosturesBySearch('abo');
        expect(returned2.length).to.be.equal(0);


    });


    it('getDevicePosturesAll', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.devicePostures = [];
        await configService.init();
        let posture: DevicePosture = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2'],
            os: 'darwin',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveDevicePosture(posture);

        let posture2: DevicePosture = {
            id: Util.randomNumberString(),
            name: 'south',
            isEnabled: true,
            labels: ['test'],
            os: 'darwin',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveDevicePosture(posture2);

        const returned = await configService.getDevicePosturesAll();
        expect(returned.length).to.be.equal(2);


    });

    it('saveDevicePosture', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.devicePostures = [];
        await configService.init();
        let posture: DevicePosture = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2'],
            os: 'ios',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveDevicePosture(posture);

        posture.name = 'north2';
        //add
        await configService.saveDevicePosture(posture);

        const returned = await configService.getDevicePosture(posture.id);

        expectToDeepEqual(returned, posture);

    });

    it('deleteDevicePosture', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);


        configService.config.devicePostures = [];
        configService.config.authenticationPolicy.rules = [];
        configService.config.authenticationPolicy.rulesOrder = [];
        await configService.init();
        let posture: DevicePosture = {
            id: Util.randomNumberString(),
            name: 'north',
            isEnabled: true,
            labels: ['test2'],
            os: 'darwin',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()

        }
        //add
        await configService.saveDevicePosture(posture);

        //save a rule
        //save a authentication rule
        let aRule: AuthenticationRule = {
            id: 'someid',
            name: 'test',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isEnabled: true,
            networkId: 'abc',
            profile: {
                device: { postures: [posture.id] }
            },
            userOrgroupIds: []

        };


        configService.config.authenticationPolicy.rules.push(aRule);
        await configService.saveAuthenticationPolicyRule(aRule);

        await configService.deleteDevicePosture(posture.id);

        const returned = await configService.getDevicePosture(posture.id)

        expect(returned).not.exist;
        const rule = await configService.getAuthenticationPolicyRule(aRule.id)
        expect(rule?.profile.device?.postures?.length).to.equal(0);

    });


    it('getFqdnIntelligenceSources/saveFqdnIntelligenceSource/deleteFqdnIntelligenceSource', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.fqdnIntelligence.sources = [];
        await configService.init();

        const source = await configService.getFqdnIntelligenceSources();
        expect(source.length).to.equal(0);

        const item = { name: 'test', type: 'test2', id: Util.randomNumberString(), insertDate: '', updateDate: '' };
        await configService.saveFqdnIntelligenceSource(item);

        const source2 = await configService.getFqdnIntelligenceSources();
        expect(source2.length).to.equal(1);

        await configService.deleteFqdnIntelligenceSource(item.id);
        const source3 = await configService.getFqdnIntelligenceSources();
        expect(source3.length).to.equal(0);


    });

    it('getFqdnIntelligenceList/saveFqdnIntelligenceList/deleteFqdnIntelligenceList', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.fqdnIntelligence.sources = [];
        await configService.init();

        const lists = await configService.getFqdnIntelligenceLists();
        expect(lists.length).to.equal(0);

        const item = { name: 'test', type: 'test2', id: Util.randomNumberString(), insertDate: '', updateDate: '' };
        await configService.saveFqdnIntelligenceList(item);

        const source2 = await configService.getFqdnIntelligenceLists();
        expect(source2.length).to.equal(1);

        const source3 = await configService.getFqdnIntelligenceList(source2[0].id);
        expect(source3).exist;

        await configService.deleteFqdnIntelligenceSource(item.id);
        const source4 = await configService.getFqdnIntelligenceSources();
        expect(source4.length).to.equal(0);


    });


    it('getHttpToHttpsRedirect/setHttpToHttpsRedirect', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.httpToHttpsRedirect = true;
        await configService.init();
        expect(configService.config.httpToHttpsRedirect).to.be.true;

        await configService.setHttpToHttpsRedirect(false);
        const db = await configService.getHttpToHttpsRedirect()
        expect(db).to.be.false;


    });
    it('getBrand/setBrand', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.brand = {};
        await configService.init();
        expect(configService.config.brand.name).not.exist;

        await configService.setBrand({ name: 'test' });
        const db = await configService.getBrand();
        expect(db.name).to.equal('test');


    });







});



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
import { ConfigEvent } from '../src/model/config';

import chaiExclude from 'chai-exclude';
import { ConfigWatch, RedisConfigService } from '../src/service/redisConfigService';
import { RedisService } from '../src/service/redisService';
import { config } from 'process';
import { WatchItem } from '../src/service/watchService';
import { authenticate } from 'passport';
import { SystemLogService } from '../src/service/systemLogService';

chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);


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
        configService.logWatcher.events.on('data', (data: WatchItem<ConfigWatch<User>>) => {
            logs.push(data.val);
        })
        //await configService.logWatcher.read();
        await configService.rSave('users', undefined, { id: 1 });
        await configService.rDel('users', { id: 1 });
        const data = await configService.rExists('users/1')
        expect(data).to.be.false;
        await Util.sleep(1000);
        await configService.logWatcher.read();
        await configService.logWatcher.read();
        await configService.logWatcher.read();
        await configService.logWatcher.read();
        await Util.sleep(10000);
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
        expect(aUserDb).to.excluding(['password']).deep.equal(aUser);

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
        expect(aUserDb).to.excluding(['password']).deep.equal(aUser);

    });

    it('getUserByApiKey', async () => {

        //first create a config and save to a redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
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
        await configService.init();
        const userDb = await configService.getUserByApiKey('1fviqq286bmcm');
        expect(userDb?.id).to.equal('6hiryy8ujv3n');

    });

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
        expect(user).to.excluding(['password']).deep.equal(aUser);

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
        const userDb = await configService.getUser(fakeUser.id)
        expect(userDb).not.exist;

        await configService.deleteUser(aUser.id);
        const userDb2 = await configService.getUser(aUser.id)
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
        configService.config.jwtSSLCertificate = {};
        await configService.init();

        await configService.setJWTSSLCertificate({ privateKey: 'a' });
        const db = await configService.getJWTSSLCertificate()
        expect(db.privateKey).to.equal('a');

    });

    it('setCASSLCertificate/getCASSLCertificate', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.caSSLCertificate = {};
        await configService.init();

        await configService.setCASSLCertificate({ privateKey: 'b', publicKey: 'c' });
        const db = await configService.getCASSLCertificate()
        expect(db.privateKey).to.equal('b');

        const db2 = await configService.getCASSLCertificatePublic()
        expect(db2).to.equal('c');

    });

    it('setLogo/getLogo', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.logo = {};
        await configService.init();

        await configService.setLogo({ default: 'a' });
        const db = await configService.getLogo()
        expect(db.default).to.equal('a');


    });

    it('setAuthSettings/getAuthSettings', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.auth = {
            common: {},
            local: {} as AuthLocal,
            ldap: {
                providers: [
                    { id: '1' } as BaseLdap
                ]
            },
            oauth: {
                providers: [
                    { id: '1' } as BaseOAuth
                ]
            },
            saml: {
                providers: [
                    { id: '1' } as BaseSaml
                ]
            }

        };

        await configService.init();

        await configService.setAuthSettings({
            common: {},
            local: {} as AuthLocal,
            ldap: {
                providers: [
                    { id: '2' } as BaseLdap
                ]
            },
            oauth: {
                providers: [
                    { id: '3' } as BaseOAuth
                ]
            },
            saml: {
                providers: [
                    { id: '4' } as BaseSaml
                ]
            }

        });
        const db = await configService.getAuthSettings()
        expect(db.ldap?.providers[0].id).to.equal('2');
        expect(db.oauth?.providers[0].id).to.equal('3');


    });


    it('authSettingsCommon', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        await configService.init();
        let common: AuthCommon = {
            bla: 'test'
        }
        await configService.setAuthSettingsCommon(common);
        const returned = await configService.getAuthSettingsCommon() as any;
        expect(returned).to.be.exist;
        expect(returned.bla).exist;

    });

    it('authSettingsOAuth', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.auth = {
            common: {}, local: {} as any
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

    it('setAuthSettingsLocal/getAuthSettingsLocal', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.auth = {
            common: {}, local: {} as any
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
        await configService.setAuthSettingsLocal(local);

        const returned = await configService.getAuthSettingsLocal();
        expect(returned).to.excluding(['insertDate', 'updateDate']).deep.equal(local);


    });


    it('authSettingsLdap', async () => {

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.auth = {
            common: {}, local: {} as any, ldap: { providers: [] }
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
        expect(returned.providers[0]).to.excluding(['insertDate', 'updateDate']).deep.equal(ldap);
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
            common: {}, local: {} as any, ldap: { providers: [] }
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
        expect(returned.providers[0]).to.excluding(['insertDate', 'updateDate']).deep.equal(saml);
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
        expect(networkDb).to.excluding(['insertDate', 'updateDate']).deep.equal(network);
        const networkDb2 = await configService.getNetworkByName('default2');
        expect(networkDb2).to.excluding(['insertDate', 'updateDate']).deep.equal(network);

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
        expect(networkDb).to.excluding(['insertDate', 'updateDate']).deep.equal(network);

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
        expect(gatewayDb).to.excluding(['insertDate', 'updateDate']).deep.equal(gateway);

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
        expect(returned).to.excluding(['insertDate', 'updateDate']).deep.equal(group);


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
        //expect(returned[0]).to.excluding(['insertDate', 'updateDate']).deep.equal(group);

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

        expect(returned).to.excluding(['insertDate', 'updateDate']).deep.equal(group);

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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.services = [];
        await configService.init();
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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.services = [];
        await configService.init();
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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.services = [];
        await configService.init();
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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.services = [];
        await configService.init();
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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);

        configService.config.groups = [];
        await configService.init();

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

        //first create a config and save to redis
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, 'redisConfig', filename);
        configService.config.authenticationPolicy.rules = [];
        await configService.init();
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
            action: 'allow',
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
            action: 'allow',
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
        let configService = new RedisConfigService(redis, redisStream, systemLogService, encKey, filename);
        configService.config.authenticationPolicy.rules = [];
        configService.config.authenticationPolicy.rulesOrder = [];
        await configService.init();
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
        await configService.logWatcher.trim(1);
        configService.logWatcher.events.on('data', (data: any) => {

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
        await configService.saveAuthenticationPolicyRule(rule2);

        await configService.deleteUser(aUser.id);
        const users = await configService.getUserByUsername(aUser.username);
        const authenticationPolicy = await configService.getAuthenticationPolicy();
        const authorizationPolicy = await configService.getAuthorizationPolicy();
        expect(authorizationPolicy.rules.find(x => x.userOrgroupIds.includes(aUser.id))).to.not.exist;
        expect(authenticationPolicy.rules.find(x => x.userOrgroupIds.includes(aUser.id))).to.not.exist;

        await configService.logWatcher.read();
        await configService.logWatcher.read();
        await configService.logWatcher.read();
        await configService.logWatcher.read();
        await configService.logWatcher.read();


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
        await configService.logWatcher.trim(1);
        configService.logWatcher.events.on('data', (data: any) => {

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
        await configService.logWatcher.read();
        await configService.logWatcher.read();
        await configService.logWatcher.read();
        await configService.logWatcher.read();
        await configService.logWatcher.read();

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
        await configService.logWatcher.trim(1);
        configService.logWatcher.events.on('data', (data: any) => {

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
            host: '1.2.3.4',
            networkId: network.id,
            tcp: 3306,
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

        await configService.logWatcher.read();
        await configService.logWatcher.read();

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
        await configService.logWatcher.trim(1);
        configService.logWatcher.events.on('data', (data: any) => {

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

        await configService.logWatcher.read();
        await configService.logWatcher.read();
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
        await configService.logWatcher.trim(1);
        configService.logWatcher.events.on('data', (data: any) => {

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
        await configService.saveAuthenticationPolicyRule(rule2);

        await configService.deleteGroup(aGroup.id);
        const authorizationPolicy = await configService.getAuthorizationPolicy();
        const authenticationPolicy = await configService.getAuthenticationPolicy();
        expect(authorizationPolicy.rules.find(x => x.userOrgroupIds.includes(aGroup.id))).to.not.exist;
        expect(authenticationPolicy.rules.find(x => x.userOrgroupIds.includes(aUser.id))).to.not.exist;

        await configService.logWatcher.read();
        await configService.logWatcher.read();

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
        await configService.logWatcher.trim(1);
        configService.logWatcher.events.on('data', (data: any) => {

            logs.push(data);
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

        await configService.logWatcher.read();
        await configService.logWatcher.read();

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








});

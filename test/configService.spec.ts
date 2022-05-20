
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs, { read } from 'fs';
import { ConfigService } from '../src/service/configService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';


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
            email: 'hamza.kilic@ferrumgate.com',
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
            email: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        configService.saveConfigToFile();
        expect(fs.existsSync(filename));

        let result = configService.loadConfigFromFile();
        expect(configService.config.users[0].id).to.equal('someid2');

    });

    it('saveConfigToString', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            email: 'hamza.kilic@ferrumgate.com',
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
            email: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        const user = await configService.getUserByEmail('hamza.kilic@ferrumgate.com');
        delete aUser.password;
        expect(user).to.deep.include(aUser);

    });

    it('getUserByEmailAndPass', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            email: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: Util.bcryptHash('passwordWithHash'), groupIds: [],
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        };

        configService.config.users.push(aUser);
        const user = await configService.getUserByEmailAndPass('hamza.kilic@ferrumgate.com', 'passwordWithHash');
        delete aUser.password;
        expect(user).to.deep.include(aUser);

        const user2 = await configService.getUserByEmailAndPass('hamza.kilic@ferrumgate.com', 'passwordWithHash2');

        expect(user2).to.be.undefined;

    });
    it('getUserById', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            email: 'hamza.kilic@ferrumgate.com',
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
            email: 'hamza.kilic@ferrumgate.com',
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
        const userDb = await configService.getUserByEmail('hamza.kilic@ferrumgate.com');
        expect(userDb?.id).to.equal('someid');

    });

    it('getUserByApiKey', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: '6hiryy8ujv3n',
            email: 'hamza.kilic@ferrumgate.com',
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
});

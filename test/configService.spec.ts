
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs, { read } from 'fs';
import { ConfigService } from '../src/service/configService';
import { app } from '../src/index';
import { User } from '../src/model/user';


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
            password: 'passwordWithHash', groupIds: []
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
            password: 'passwordWithHash', groupIds: []
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
            password: 'passwordWithHash', groupIds: []
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
            password: 'passwordWithHash', groupIds: []
        };

        configService.config.users.push(aUser);
        const user = await configService.getUserByEmail('hamza.kilic@ferrumgate.com');
        expect(user).to.equal(aUser);

    });
    it('getUserById', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            email: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: []
        };

        configService.config.users.push(aUser);
        const user = await configService.getUserById('someid');
        expect(user).to.equal(aUser);

    });
    it('saveUser', async () => {

        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        let aUser: User = {
            id: 'someid',
            email: 'hamza.kilic@ferrumgate.com',
            name: 'test', source: 'local',
            password: 'passwordWithHash', groupIds: []
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
});

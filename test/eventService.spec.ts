
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { ConfigService } from '../src/service/configService';
import { Util } from '../src/util';
import { RedisService } from '../src/service/redisService';
import { EventService } from '../src/service/eventService';



chai.use(chaiHttp);
const expect = chai.expect;




describe.skip('eventService', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const configService = new ConfigService('kgWn7f1dtNOjuYdjezf0dR5I3HQIMNrGsUqthIsHHPoeqt', filename);
    const redisService = new RedisService();

    before(async () => {
        await configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await configService.saveConfigToFile();
        await configService.loadConfigFromFile();
    })
    beforeEach(async () => {
        await redisService.flushAll();
    })
    it('test events', async () => {
        const event = new EventService(configService, redisService);
        const redisServiceSub = new RedisService();
        let channelName = '';
        let channelMessage = '';
        redisServiceSub.onMessage((channel: string, message) => {
            channelName = channel;
            channelMessage = message;
        })
        configService.emitEvent({ type: 'saved', path: '/users', data: { id: 'asd' } })
        Util.sleep(1000);
        expect(channelName).exist;
        expect(channelMessage).exist;

    }).timeout(5000);


})



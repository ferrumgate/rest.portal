
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { TemplateService } from '../src/service/templateService';
import { ConfigService } from '../src/service/configService';
import { Util } from '../src/util';
import { RedisService } from '../src/service/redisService';
import { EventService } from '../src/service/eventService';
import { Gateway, GatewayDetail } from '../src/model/network';
import os from 'os';
import { GatewayService } from '../src/service/gatewayService';


chai.use(chaiHttp);
const expect = chai.expect;




describe('gatewayService', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const configService = new ConfigService('kgWn7f1dtNOjuYdjezf0dR5I3HQIMNrGsUqthIsHHPoeqt', filename);
    const redisService = new RedisService();

    before(async () => {
        await configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await configService.saveConfigToFile();
        await configService.loadConfigFromFile();
    })
    beforeEach(async () => {
        await (app.appService as AppService).redisService.flushAll();
    })
    it('getAllAlive', async () => {

        const redisService = new RedisService();
        let detail: GatewayDetail = {
            id: Util.randomNumberString(),
            arch: os.arch(),
            cpusCount: os.cpus().length,
            cpuInfo: os.cpus().find(x => x)?.model,
            hostname: os.hostname(),
            totalMem: os.totalmem(),
            type: os.type(),
            uptime: os.uptime(),
            version: os.version(),
            platform: os.platform(),
            release: os.release(),
            freeMem: os.freemem(),
            interfaces: JSON.stringify(os.networkInterfaces()),
            lastSeen: new Date().getTime()

        }
        await redisService.hset(`/host/id/${detail.id}`, detail);
        const gw = new GatewayService(configService, redisService);
        const items = await gw.getAllAlive();
        expect(items.length).to.equal(1);
        expect(items[0]).to.deep.equal(detail);

    }).timeout(5000);
    it('getAliveById', async () => {

        const redisService = new RedisService();
        let detail: GatewayDetail = {
            id: Util.randomNumberString(),
            arch: os.arch(),
            cpusCount: os.cpus().length,
            cpuInfo: os.cpus().find(x => x)?.model,
            hostname: os.hostname(),
            totalMem: os.totalmem(),
            type: os.type(),
            uptime: os.uptime(),
            version: os.version(),
            platform: os.platform(),
            release: os.release(),
            freeMem: os.freemem(),
            interfaces: JSON.stringify(os.networkInterfaces()),
            lastSeen: new Date().getTime()

        }
        await redisService.hset(`/host/id/${detail.id}`, detail);
        const gw = new GatewayService(configService, redisService);
        const item = await gw.getAliveById(detail.id)
        expect(item).to.deep.equal(detail);

        const item2 = await gw.getAliveById('unknownid');
        expect(item2).not.exist;

    }).timeout(5000);


})



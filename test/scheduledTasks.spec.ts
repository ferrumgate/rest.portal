import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import fsp from 'fs/promises';
import { ClearTmpFolderTask, ImportExternalConfigTask } from '../src/service/system/scheduledTasks';
import { Util } from '../src/util';
import { RedisService } from '../src/service/redisService';
import { SystemLogService } from '../src/service/systemLogService';
import { RedisConfigService } from '../src/service/redisConfigService';

chai.use(chaiHttp);
const expect = chai.expect;

describe('ScheduledTasks', async () => {
    const encKey = 'u88aapisbdvmufeptows0a5l53sa1r3v';
    const redis = new RedisService();
    const redisStream = new RedisService();
    const systemlog = new SystemLogService(redis, redisStream, encKey, 'testme');
    const configService = new RedisConfigService(redis, redisStream, systemlog, encKey, 'testme2');
    beforeEach(async () => {
        await redis.flushAll();
    })
    it('ClearTmpFolderTask', async () => {
        const folder = `/tmp/${Util.randomNumberString()}`;
        await fsp.mkdir(folder, { recursive: true })
        const filename = `${folder}/${Util.randomNumberString()}`;
        await fsp.writeFile(filename, "test");

        const folder2 = `${folder}/${Util.randomNumberString()}`;
        await fsp.mkdir(folder2, { recursive: true })
        const filename2 = `${folder2}/${Util.randomNumberString()}`;
        await fsp.writeFile(filename2, "test");

        await Util.sleep(1000);
        expect(fs.existsSync(filename)).to.be.true;
        expect(fs.existsSync(filename2)).to.be.true;

        const tmpClear = new ClearTmpFolderTask(folder);
        await tmpClear.clearUploadFolder(1);

        expect(fs.existsSync(filename)).to.be.false;
        expect(fs.existsSync(filename2)).to.be.false;
        //create new folder
        const filename3 = `${folder}/${Util.randomNumberString()}`;
        await fsp.writeFile(filename3, "test");
        await Util.sleep(1000);

        await tmpClear.start(500);
        await Util.sleep(2000);
        await tmpClear.stop();
        expect(fs.existsSync(filename2)).to.be.false;

    }).timeout(5000);

    it('ImportExternalConfigTask', async () => {
        await configService.init();
        const filename = `/tmp/${Util.randomNumberString()}`;
        const externalConfigTask = new ImportExternalConfigTask(1000,
            configService, filename);
        let result = await externalConfigTask.checkConfigFile();
        expect(result).to.be.false;

        //empty config
        await fsp.writeFile(filename, `FERRUM_CLOUD_CONFIG=`);
        result = await externalConfigTask.checkConfigFile();
        expect(result).to.be.false;

        // throw error
        await fsp.writeFile(filename, `FERRUM_CLOUD_CONFIG=aadfa`);
        result = await externalConfigTask.checkConfigFile();
        expect(result).to.be.false;

        // parses data
        const externalConfig = { captcha: { externalId: Util.randomNumberString(), client: '1', server: '2' } };
        const data = JSON.stringify(externalConfig);
        const base64 = Buffer.from(data).toString('base64');
        await fsp.writeFile(filename, `FERRUM_CLOUD_CONFIG=${base64}`);
        result = await externalConfigTask.checkConfigFile();
        expect(result).to.be.true;
        const captcha = await configService.getCaptcha();
        expect(captcha.client).to.be.eq('1');
        expect(captcha.server).to.be.eq('2');
        const externalConfigIds = await configService.getExternalConfig();
        expect(externalConfigIds.ids?.includes(externalConfig.captcha.externalId)).to.be.true;
        // check if file changed
        result = await externalConfigTask.checkConfigFile();
        expect(result).to.be.false;






    }).timeout(35000);

})


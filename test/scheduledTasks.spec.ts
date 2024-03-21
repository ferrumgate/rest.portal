import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import fsp from 'fs/promises';
import { ClearTmpFolderTask } from '../src/service/system/scheduledTasks';
import { Util } from '../src/util';

chai.use(chaiHttp);
const expect = chai.expect;

describe('ScheduledTasks', async () => {

    beforeEach(async () => {

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

})


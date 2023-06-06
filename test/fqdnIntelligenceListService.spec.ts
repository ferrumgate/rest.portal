
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { ConfigService } from '../src/service/configService';
import { Util } from '../src/util';
import { RedisService } from '../src/service/redisService';
import { GatewayDetail } from '../src/model/network';
import os from 'os';
import { GatewayService } from '../src/service/gatewayService';
import chaiExclude from 'chai-exclude';
import crypto from 'node:crypto';
import { InputService } from '../src/service/inputService';
import { ESService } from '../src/service/esService';
import { FqdnIntelligenceListService } from '../src/service/fqdnIntelligenceService';
import { FqdnIntelligenceList } from '../src/model/fqdnIntelligence';
import { FqdnIntelligenceListStatus } from '../src/model/fqdnIntelligence';
import { FqdnIntelligenceListFiles } from '../src/model/fqdnIntelligence';
import { esHost, esPass, esUser } from './common.spec';



chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);

function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete b.insertDate;
    delete b.updateDate;
    expect(a).to.deep.equal(b);
}


describe('fqdnIntelligenceListService', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const configService = new ConfigService('kgWn7f1dtNOjuYdjezf0dR5I3HQIMNrGsUqthIsHHPoeqt', filename);
    const redisService = new RedisService();
    const inputService = new InputService();
    const esService = new ESService(configService, esHost, esUser, esPass, '1s');

    before(async () => {
        await configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await configService.setES({ host: esHost, user: esUser, pass: esPass });
        await configService.saveConfigToFile();
        await configService.loadConfigFromFile();
    })
    beforeEach(async () => {
        await redisService.flushAll();
        await esService.reset();
        await Util.sleep(1000);
    })
    it('downloadFileFromRedis', async () => {
        const data = crypto.randomBytes(4 * 1024 * 1024);
        await redisService.set("/test", data);
        const data2 = await redisService.get("/test", false);
        const tmpFile = `/tmp/${Util.randomNumberString()}`;
        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);
        await intel.downloadFileFromRedis("/test", tmpFile);
        expect(fs.existsSync(tmpFile)).to.be.true;



    }).timeout(500000);
    it('downloadFileFromRedis', async () => {
        const data = crypto.randomBytes(4 * 1024 * 1024);
        await redisService.hset("/test", { test: data });
        const tmpFile = `/tmp/${Util.randomNumberString()}`;
        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);
        await intel.downloadFileFromRedisH("/test", 'test', tmpFile, 'test', '/tmp');
        expect(fs.existsSync(tmpFile)).to.be.true;

    }).timeout(500000);

    it('splitFile', async () => {

        const tmpFolder = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\ncom\n.co.uk\n//testme\n*.test.me");
        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);
        const files = await intel.splitFile(tmpFolder, tmpFolderFile, 10000);
        expect(files.length).to.equal(4);
        expect(files[0].page = 6706);
        expect(files[0].hash).exist;
        expect(files[0].filename).exist;


    }).timeout(500000);


    it('getListStatus/saveListStatus/deleteListStatus', async () => {


        const item: FqdnIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '', labels: [],
        }
        const status: FqdnIntelligenceListStatus = {
            id: item.id,
            hash: 'adfa', lastCheck: 'adf', lastError: '',
        }

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);
        await intel.saveListStatus(item, status);

        const data = await intel.getListStatus(item);
        expectToDeepEqual(data, status);

        await intel.deleteListStatus(item);

        const data2 = await intel.getListStatus(item);
        expect(data2).not.exist;



    }).timeout(500000);

    it('getDbFileList/saveDbFileList/deleteDbFileList/deleteDbFileList2', async () => {

        const item: FqdnIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '', labels: [],
        }

        const files: FqdnIntelligenceListFiles = {
            '0': { page: 5, hash: "string" },
            '1110': { page: 5, hash: "string" }
        }

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);
        await intel.saveDbFileList(item, files);

        const files2 = await intel.getDbFileList(item);
        expectToDeepEqual(files, files2);


        await intel.deleteDbFileList2(item, 0);


        const files3 = await intel.getDbFileList(item);
        expect(files3).exist;
        if (files3)
            expect(files3['0']).not.exist;

        await intel.deleteDbFileList(item);

        const files4 = await intel.getDbFileList(item);
        expect(files4).exist;
        if (files4)
            expect(Object.keys(files4).length == 0).to.be.true;

    })


    it('saveToStore/delStore', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\nyahoo.com\nferrumgate.com");
        const item: FqdnIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
        }

        const files: FqdnIntelligenceListFiles = {
            '0': { page: 5, hash: "string" },
            '1110': { page: 5, hash: "string" }
        }

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);
        await intel.saveToStore(item, tmpFolderFile, 0);
        await Util.sleep(1000);
        const listId = await intel.getByFqdn(item.id, 'www.google.com')
        expect(listId).exist;



        await intel.deleteFromStore(item, 0);
        await Util.sleep(1000);
        const listId2 = await intel.getByFqdn(item.id, 'google2.com')
        expect(listId2).not.exist;



    })

    it('process file version', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\ncom\nferrumgate.com");
        const item: FqdnIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);

        await intel.saveListFile(item, tmpFolderFile);
        const status = await intel.getListStatus(item);
        expect(status).not.exist;

        //process first
        await intel.process(item);

        const status2 = await intel.getListStatus(item);
        expect(status2).exist;
        expect(status2?.isChanged).to.be.true;

        //process again ischanged false
        await intel.process(item);
        const status3 = await intel.getListStatus(item);
        expect(status3).exist;
        expect(status3?.lastCheck).not.equal(status2?.lastCheck);
        expect(status3?.isChanged).to.be.false;


        fs.writeFileSync(tmpFolderFile, "www.google.com\ncom\nferrumgate.com\nco.uk");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);
        const status4 = await intel.getListStatus(item);
        expect(status4).exist;
        expect(status4?.lastCheck).not.equal(status3?.lastCheck);
        expect(status4?.isChanged).to.be.true;



        fs.writeFileSync(tmpFolderFile, "www.google.com\ncom\nferrumgate.com\nco.uk\nio");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);




    }).timeout(50000);


    it('process http version', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);

        const item: FqdnIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            http: {
                url: 'https://v.firebog.net/hosts/static/w3kbl.txt',
                checkFrequency: 1
            }
        }

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);


        const status = await intel.getListStatus(item);
        expect(status).not.exist;

        //process first
        await intel.process(item);

        const status2 = await intel.getListStatus(item);
        expect(status2).exist;
        expect(status2?.isChanged).to.be.true;

        //process again ischanged false
        await intel.process(item);
        const status3 = await intel.getListStatus(item);
        expect(status3).exist;
        expect(status3?.lastCheck).not.equal(status2?.lastCheck);
        expect(status3?.isChanged).to.be.false;


    }).timeout(50000);



    it('deleteList', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\ncom\nferrumgate.com\nco.uk");
        const item: FqdnIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);

        await intel.saveListFile(item, tmpFolderFile);
        const status = await intel.getListStatus(item);
        expect(status).not.exist;

        //process first
        await intel.process(item);

        const keys1 = await redisService.getAllKeys('*');
        expect(keys1.length > 0).to.be.true;

        //process again ischanged false
        await intel.deleteList(item);

        const keys = await redisService.getAllKeys('*');
        expect(keys.length).to.equal(0);




    }).timeout(50000);


    it('getAllListItems', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\ncom\nferrumgate.com\nco.uk");
        const item: FqdnIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);

        fs.writeFileSync(tmpFolderFile, "www.google.com\ncom\nferrumgate.com\nco.uk\nwww.yahoo.com");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);
        await Util.sleep(1000);

        let items = await intel.getAllListItems(item, () => true);
        expect(items.length).to.equal(5);
        expect(items.includes('www.yahoo.com')).to.be.true;
        expect(items.includes('co.uk')).to.be.true;
        console.log(items);



    }).timeout(120000);


    it('getByFqdn', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;

        const item: FqdnIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);

        fs.writeFileSync(tmpFolderFile, "www.google.com\ncom\nferrumgate.com\nco.uk");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);
        await Util.sleep(1000);

        const id = await intel.getByFqdn(item.id, 'www.google.com')
        expect(id).exist;

        const id2 = await intel.getByFqdn(item.id, 'com')
        expect(id2).exist;

        const id3 = await intel.getByFqdn(item.id, 'ferrumgate.com')
        expect(id3).exist;



        const id8 = await intel.getByFqdn(item.id, 'www.amazon.com')
        expect(id8).not.exist;

    }).timeout(50000);






    it('getByFqdnAll', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);

        //first file
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;

        const item: FqdnIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);

        fs.writeFileSync(tmpFolderFile, "www.google.com\ncom\nferrumgate.com\nco.uk");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);

        //second file

        const tmpFolderFile2 = `${tmpFolder}/${Util.randomNumberString()}`;

        const item2: FqdnIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }



        fs.writeFileSync(tmpFolderFile2, "www.google.com\ncom\nferrumgate.com");
        await intel.saveListFile(item2, tmpFolderFile2);
        //process again ischanged false
        await intel.process(item2);

        await Util.sleep(1000);

        const id = await intel.getByFqdnAll('ferrumgate.com')
        expect(id.items.length == 2).to.be.true;
        expect(id.items.find(x => x == item.id)).exist
        expect(id.items.find(y => y == item2.id)).exist;




    }).timeout(50000);


    it('compareSystemHealth', async () => {

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);

        await redisService.set('/intelligence/fqdn/list/1/file', 0);
        await redisService.set('/intelligence/fqdn/list/1/status', 0);
        await intel.compareSystemHealth([{ id: '2' } as any]);
        const item = await redisService.get('/intelligence/fqdn/list/1/file', false);
        expect(item).not.exist;



    }).timeout(50000);

    it('prepareFile', async () => {

        const intel = new FqdnIntelligenceListService(redisService, inputService, esService);
        const baseFolder = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(baseFolder);

        const filenameZip = `${baseFolder}/${Util.randomNumberString()}`
        fs.copyFileSync('./test/data/test.zip', filenameZip);
        await intel.prepareFile('test.zip', filenameZip, baseFolder);
        const contentZip = fs.readFileSync(filenameZip).toString();
        expect(contentZip).to.equal('something');



        const filenameTarGz = `${baseFolder}/${Util.randomNumberString()}`
        fs.copyFileSync('./test/data/test.tar.gz', filenameTarGz);
        await intel.prepareFile('test.tar.gz', filenameTarGz, baseFolder);
        const contentTarGz = fs.readFileSync(filenameTarGz).toString();
        expect(contentTarGz).to.equal('something');


    }).timeout(50000);

    /*     it('manuel', async () => {
    
            const item2: FqdnIntelligenceList = {
                id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
                labels: [],
                http: {
                    url: 'https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt',
                    checkFrequency: 1
                },
                splitter: ' ', splitterIndex: 1
            }
    
            const intel = new FqdnIntelligenceListService(redisService, inputService, esService);
            await intel.process(item2)
            console.log(intel);
    
    
        }).timeout(50000); */






})



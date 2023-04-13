
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
import {
    IpIntelligenceList, IpIntelligenceListFiles, IpIntelligenceListStatus,
    IpIntelligenceSource
} from '../src/model/IpIntelligence';
import { IpIntelligenceListService, IpIntelligenceService } from '../src/service/ipIntelligenceService';
import crypto from 'node:crypto';
import { InputService } from '../src/service/inputService';
import { ESService } from '../src/service/esService';



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

const eshost = 'https://192.168.88.250:9200';
const esuser = 'elastic';
const espass = '123456';

describe('ipIntelligenceListService', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const configService = new ConfigService('kgWn7f1dtNOjuYdjezf0dR5I3HQIMNrGsUqthIsHHPoeqt', filename);
    const redisService = new RedisService();
    const inputService = new InputService();
    const esService = new ESService(configService, eshost, esuser, espass, '1s');

    before(async () => {
        await configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await configService.setES({ host: eshost, user: esuser, pass: espass });
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
        const intel = new IpIntelligenceListService(redisService, inputService, esService);
        await intel.downloadFileFromRedis("/test", tmpFile);
        expect(fs.existsSync(tmpFile)).to.be.true;



    }).timeout(500000);
    it('downloadFileFromRedis', async () => {
        const data = crypto.randomBytes(4 * 1024 * 1024);
        await redisService.hset("/test", { test: data });
        const tmpFile = `/tmp/${Util.randomNumberString()}`;
        const intel = new IpIntelligenceListService(redisService, inputService, esService);
        await intel.downloadFileFromRedisH("/test", 'test', tmpFile, 'test', '/tmp');
        expect(fs.existsSync(tmpFile)).to.be.true;

    }).timeout(500000);

    it('splitFile', async () => {

        const tmpFolder = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n8.8.8.8\n//testme");
        const intel = new IpIntelligenceListService(redisService, inputService, esService);
        const files = await intel.splitFile(tmpFolder, tmpFolderFile, 10000);
        expect(files.length).to.equal(3);
        expect(files[0].page = 6706);
        expect(files[0].hash).exist;
        expect(files[0].filename).exist;


    }).timeout(500000);


    it('getListStatus/saveListStatus/deleteListStatus', async () => {


        const item: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '', labels: [],
        }
        const status: IpIntelligenceListStatus = {
            id: item.id,
            hash: 'adfa', lastCheck: 'adf', lastError: '',
        }

        const intel = new IpIntelligenceListService(redisService, inputService, esService);
        await intel.saveListStatus(item, status);

        const data = await intel.getListStatus(item);
        expectToDeepEqual(data, status);

        await intel.deleteListStatus(item);

        const data2 = await intel.getListStatus(item);
        expect(data2).not.exist;



    }).timeout(500000);

    it('getDbFileList/saveDbFileList/deleteDbFileList/deleteDbFileList2', async () => {

        const item: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '', labels: [],
        }

        const files: IpIntelligenceListFiles = {
            '0': { page: 5, hash: "string" },
            '1110': { page: 5, hash: "string" }
        }

        const intel = new IpIntelligenceListService(redisService, inputService, esService);
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
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n8.8.8.8");
        const item: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
        }

        const files: IpIntelligenceListFiles = {
            '0': { page: 5, hash: "string" },
            '1110': { page: 5, hash: "string" }
        }

        const intel = new IpIntelligenceListService(redisService, inputService, esService);
        await intel.saveToStore(item, tmpFolderFile, 0);
        await Util.sleep(1000);
        const listId = await intel.getByIp(item.id, '1.1.1.1')
        expect(listId).exist;



        await intel.deleteFromStore(item, 0);
        await Util.sleep(1000);
        const listId2 = await intel.getByIp(item.id, '1.1.1.1')
        expect(listId2).not.exist;



    })

    it('process file version', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n8.8.8.8");
        const item: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new IpIntelligenceListService(redisService, inputService, esService);

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


        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n8.8.8.8\n3.3.3.3");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);
        const status4 = await intel.getListStatus(item);
        expect(status4).exist;
        expect(status4?.lastCheck).not.equal(status3?.lastCheck);
        expect(status4?.isChanged).to.be.true;



        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n9.8.8.8\n8.8.8.8\n3.3.3.3");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);




    }).timeout(50000);


    it.skip('process http version', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);

        const item: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            http: {
                url: 'https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/022/328/original/ip_filter.blf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMJQBJPARJ%2F20230321%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230321T144308Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=44af69f4e0b1cfad5cefc3ae63c5e23e6843849fe15350bd54caa959e4c5d9d1',
                checkFrequency: 1
            }
        }

        const intel = new IpIntelligenceListService(redisService, inputService, esService);


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
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n8.8.8.8");
        const item: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new IpIntelligenceListService(redisService, inputService, esService);

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
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n8.8.8.8");
        const item: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new IpIntelligenceListService(redisService, inputService, esService);

        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n9.8.8.8\n8.8.8.8\n3.3.3.3");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);
        await Util.sleep(1000);

        let items = await intel.getAllListItems(item, () => true);
        expect(items.length).to.equal(5);
        expect(items.includes('1.1.1.1/32')).to.be.true;
        expect(items.includes('192.168.0.0/24')).to.be.true;
        console.log(items);



    }).timeout(120000);


    it('getByIp', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;

        const item: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new IpIntelligenceListService(redisService, inputService, esService);

        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n9.8.8.8\n8.8.8.8\n3.3.3.3\n192.168.0.1/32\n192.168.9.10/32\n192.168.10.0/24");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);
        await Util.sleep(1000);

        const id = await intel.getByIp(item.id, '1.1.1.1')
        expect(id).exist;

        const id2 = await intel.getByIp(item.id, '192.168.0.0')
        expect(id2).exist;

        const id3 = await intel.getByIp(item.id, '192.168.0.1')
        expect(id3).exist;



        const id5 = await intel.getByIp(item.id, '192.168.1.10')
        expect(id5).not.exist;

        const id6 = await intel.getByIp(item.id, '192.168.9.10')
        expect(id6).exist;


        const id7 = await intel.getByIp(item.id, '192.168.10.15')
        expect(id7).exist;

        const id8 = await intel.getByIp(item.id, '192.168.9.11')
        expect(id8).not.exist;

    }).timeout(50000);



    it('getByIp intersection', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;

        const item: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new IpIntelligenceListService(redisService, inputService, esService);

        fs.writeFileSync(tmpFolderFile, "192.168.10.0/24\n192.168.0.0/16");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);
        await Util.sleep(1000);

        const id = await intel.getByIp(item.id, '192.168.10.1')
        expect(id).exist;

        const id2 = await intel.getByIp(item.id, '192.168.0.0')
        expect(id2).exist;

        const id3 = await intel.getByIp(item.id, '192.168.3.10')
        expect(id3).exist;



        const id5 = await intel.getByIp(item.id, '192.167.1.10')
        expect(id5).not.exist;


    }).timeout(50000);


    it('getByIpAll', async () => {
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);

        //first file
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;

        const item: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }

        const intel = new IpIntelligenceListService(redisService, inputService, esService);

        fs.writeFileSync(tmpFolderFile, "192.168.10.0/24\n192.168.0.0/16");
        await intel.saveListFile(item, tmpFolderFile);
        //process again ischanged false
        await intel.process(item);

        //second file

        const tmpFolderFile2 = `${tmpFolder}/${Util.randomNumberString()}`;

        const item2: IpIntelligenceList = {
            id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
            labels: [],
            file: {
                source: "test.txt"
            }
        }



        fs.writeFileSync(tmpFolderFile2, "192.168.10.0/24\n192.168.0.0/16");
        await intel.saveListFile(item2, tmpFolderFile2);
        //process again ischanged false
        await intel.process(item2);

        await Util.sleep(1000);

        const id = await intel.getByIpAll('192.168.10.1')
        expect(id.items.length == 2).to.be.true;
        expect(id.items.find(x => x == item.id)).exist
        expect(id.items.find(y => y == item2.id)).exist;




    }).timeout(50000);


    it('compareSystemHealth', async () => {

        const intel = new IpIntelligenceListService(redisService, inputService, esService);

        await redisService.set('/intelligence/ip/list/1/file', 0);
        await redisService.set('/intelligence/ip/list/1/status', 0);
        await intel.compareSystemHealth([{ id: '2' } as any]);
        const item = await redisService.get('/intelligence/ip/list/1/file', false);
        expect(item).not.exist;



    }).timeout(50000);

    it('prepareFile', async () => {

        const intel = new IpIntelligenceListService(redisService, inputService, esService);
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
    
            const item2: IpIntelligenceList = {
                id: Util.randomNumberString(), name: 'test', insertDate: '', updateDate: '',
                labels: [],
                http: {
                    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
                    checkFrequency: 1
                },
                splitter: ',', splitterIndex: 1
            }
    
            const intel = new IpIntelligenceListService(redisService, inputService, esService);
            await intel.process(item2)
            console.log(intel);
    
    
        }).timeout(50000); */






})



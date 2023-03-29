
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Network } from '../src/model/network';

import chaiExclude from 'chai-exclude';
import { IpIntelligence, IpIntelligenceList, IpIntelligenceListStatus, IpIntelligenceSource } from '../src/model/IpIntelligence';
import { ESService } from '../src/service/esService';


chai.use(chaiHttp);
const expect = chai.expect;
chai.use(chaiExclude);

function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete b.insertDate;
    delete b.updateDate;
    delete a.id;
    delete b.id;
    expect(a).to.deep.equal(b);
}


const eshost = 'https://192.168.88.250:9200';
const esuser = 'elastic';
const espass = '123456';

/**
 * authenticated user api tests
 */
describe('ipIntelligenceApi', async () => {
    const appService = app.appService as AppService;
    const redisService = appService.redisService;
    const sessionService = appService.sessionService;

    const user: User = {
        username: 'hamza@ferrumgate.com',
        groupIds: [],
        id: 'someid',
        name: 'hamza',
        source: 'local',
        roleIds: ['Admin'],
        isLocked: false, isVerified: true,
        password: Util.bcryptHash('somepass'),
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }
    before(async () => {
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.setJWTSSLCertificate({ privateKey: fs.readFileSync('./ferrumgate.com.key').toString(), publicKey: fs.readFileSync('./ferrumgate.com.crt').toString() });
        await appService.configService.setIsConfigured(1);
        await appService.esService.reConfigure(eshost, esuser, espass, '1s');

    })


    beforeEach(async () => {
        appService.configService.config.users = [];
        appService.configService.config.networks = [];
        appService.configService.config.gateways = [];
        appService.configService.config.ipIntelligence.sources = [];
        appService.configService.config.ipIntelligence.lists = [];
        await redisService.flushAll();
        await appService.esService.reset();
    })


    it('check authoration as admin role', async () => {
        //prepare data
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveIpIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/source`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);

    }).timeout(50000);




    //// ip intelligence source 

    it('GET /ip/intelligence/source will return items', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveIpIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/source`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.items).exist;


        expectToDeepEqual(response.body.items[0], item);



    }).timeout(50000);

    it('DELETE /ip/intelligence/source', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: IpIntelligenceSource = {
            id: Util.randomNumberString(),
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveIpIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/ip/intelligence/source/` + item.id)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        const items = await appService.configService.getIpIntelligenceSources();
        expect(items.length).to.equal(0);


    }).timeout(50000);

    it('POST /ip/intelligence/source', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: IpIntelligenceSource = {
            id: Util.randomNumberString(), apiKey: 'abc',
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        //await appService.configService.saveIpIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/ip/intelligence/source`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(item)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;

        const items = await appService.configService.getIpIntelligenceSources();
        expect(items.length).to.equal(1);


    }).timeout(50000);

    it('PUT /ip/intelligence/source', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: IpIntelligenceSource = {
            id: Util.randomNumberString(), apiKey: 'abc',
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveIpIntelligenceSource(item);
        item.apiKey = 'def'
        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/ip/intelligence/source`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(item)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body).exist;

        const items = await appService.configService.getIpIntelligenceSources();
        expect(items.length).to.equal(1);
        expect(items[0].apiKey).to.equal('def');

    }).timeout(50000);



    it('GET /ip/intelligence/list will return items', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let id = Util.randomNumberString();
        const item: IpIntelligenceList = {
            id: id, labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt' }
        }
        const status: IpIntelligenceListStatus = {
            id: item.id
        }

        await appService.configService.saveIpIntelligenceList(item);
        await appService.ipIntelligenceService.listService.saveListStatus(item, status);

        // test all 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/list`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.items).exist;
        expect(response.body.itemsStatus).exist;

        expectToDeepEqual(response.body.items[0], item);
        expectToDeepEqual(response.body.itemsStatus[0], status);


        // test search 
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/list?search=te`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.items).exist;
        expect(response.body.itemsStatus).exist;

        expectToDeepEqual(response.body.items[0], item);
        expectToDeepEqual(response.body.itemsStatus[0], status);

        // test search ip
        //prepare ips
        item.id = id;//set it back
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n9.8.8.8\n8.8.8.8\n3.3.3.3");
        await appService.ipIntelligenceService.listService.saveListFile(item, tmpFolderFile);
        //process
        await appService.ipIntelligenceService.listService.process(item);
        await Util.sleep(1000);

        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/list?search=192.168.0.4`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.items).exist;
        expect(response.body.itemsStatus).exist;

        expectToDeepEqual(response.body.items[0], item);
        expect(response.body.itemsStatus[0].hash).exist;
        console.log(response.body.itemsStatus);






    }).timeout(50000);


    it('PUT /ip/intelligence/list/id/reset will reset items', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let id = Util.randomNumberString();
        const item: IpIntelligenceList = {
            id: id, labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt' }
        }
        const status: IpIntelligenceListStatus = {
            id: item.id
        }

        await appService.configService.saveIpIntelligenceList(item);
        await appService.ipIntelligenceService.listService.saveListStatus(item, status);


        // test search ip
        //prepare ips
        item.id = id;//set it back
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n9.8.8.8\n8.8.8.8\n3.3.3.3");
        await appService.ipIntelligenceService.listService.saveListFile(item, tmpFolderFile);
        //process
        await appService.ipIntelligenceService.listService.process(item);
        await Util.sleep(1000);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/list?search=192.168.0.4`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.items).exist;
        expect(response.body.itemsStatus).exist;

        expectToDeepEqual(response.body.items[0], item);
        expect(response.body.itemsStatus[0].hash).exist;


        //reset 
        item.id = id;//set it back
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/ip/intelligence/list/${item.id}/reset`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        const result = await appService.ipIntelligenceService.listService.getByIp(item.id, '192.168.0.4')
        expect(result).not.exist;

        const result2 = await appService.ipIntelligenceService.listService.getListStatus(item);
        expect(result2).not.exist;
        const result3 = await appService.ipIntelligenceService.listService.getDbFileList(item);
        expect(Object.keys(result3 || {}).length == 0).to.be.true;


    }).timeout(50000);



    it('DELETE /ip/intelligence/list', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let id = Util.randomNumberString();
        const item: IpIntelligenceList = {
            id: id, labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt' }
        }
        const status: IpIntelligenceListStatus = {
            id: item.id
        }

        await appService.configService.saveIpIntelligenceList(item);
        await appService.ipIntelligenceService.listService.saveListStatus(item, status);


        //prepare ips
        item.id = id;//set it back
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n9.8.8.8\n8.8.8.8\n3.3.3.3");
        await appService.ipIntelligenceService.listService.saveListFile(item, tmpFolderFile);
        //process
        await appService.ipIntelligenceService.listService.process(item);
        await Util.sleep(1000);

        // test all 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/ip/intelligence/list/${item.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        await Util.sleep(1000);

        const result = await appService.configService.getIpIntelligenceList(id);
        expect(result).not.exist;
        const result2 = await appService.ipIntelligenceService.listService.getListStatus(item);
        expect(result2).not.exist;
        const listId = await appService.ipIntelligenceService.listService.getByIp(item.id, '1.1.1.1')
        expect(listId).not.exist;



    }).timeout(50000);


    it('POST /ip/intelligence/list', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const filekey = Util.randomNumberString();

        const item: IpIntelligenceList = {
            id: '',
            labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt', key: filekey }
        }

        const tmpFolder = `/tmp/uploads`;

        fs.mkdirSync(tmpFolder, { recursive: true });
        const tmpFolderFile = `${tmpFolder}/${filekey}`;
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n9.8.8.8\n8.8.8.8\n3.3.3.3");

        // test all 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/ip/intelligence/list`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(item)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const savedItem = response.body as IpIntelligenceList;

        const result = await appService.configService.getIpIntelligenceList(savedItem.id);
        expect(result).exist;
        const result2 = await redisService.exists(`/intelligence/ip/list/${savedItem.id}/file`)
        expect(result2).to.be.true;




    }).timeout(50000);



    it('PUT /ip/intelligence/list', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const filekey = Util.randomNumberString();

        const item: IpIntelligenceList = {
            id: Util.randomNumberString(),
            labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt' }
        }

        const status: IpIntelligenceListStatus = {
            id: item.id
        }

        await appService.configService.saveIpIntelligenceList(item);
        await appService.ipIntelligenceService.listService.saveListStatus(item, status);

        const tmpFolder = `/tmp/uploads`;

        fs.mkdirSync(tmpFolder, { recursive: true });
        const tmpFolderFile = `${tmpFolder}/${filekey}`;
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n9.8.8.8\n8.8.8.8\n3.3.3.3");
        item.name = 'abo';
        if (item.file)
            item.file.key = filekey;
        // test all 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/ip/intelligence/list`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(item)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const savedItem = response.body as IpIntelligenceList;

        const result: IpIntelligenceList | undefined = await appService.configService.getIpIntelligenceList(savedItem.id);
        expect(result).exist;
        expect(result?.name).to.equal('abo');
        const result2 = await redisService.exists(`/intelligence/ip/list/${savedItem.id}/file`)
        expect(result2).to.be.true;




    }).timeout(50000);


    it('POST /ip/intelligence/list/file', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const tmpFolder = `/tmp/uploads`;

        fs.mkdirSync(tmpFolder, { recursive: true });
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n9.8.8.8\n8.8.8.8\n3.3.3.3");

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/ip/intelligence/list/file`)
                .set(`Authorization`, `Bearer ${token}`)
                .set('content-type', 'multipart/form-data')
                .attach('file', tmpFolderFile, 'file.txt')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        const savedItem = response.body.key as string
        expect(savedItem).exist;
        expect(fs.existsSync('/tmp/uploads/' + savedItem)).to.be.true;




    }).timeout(50000);


    it('GET /ip/intelligence/list/:id/file', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        let id = Util.randomNumberString();
        const item: IpIntelligenceList = {
            id: id, labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt' }
        }
        const status: IpIntelligenceListStatus = {
            id: item.id
        }

        await appService.configService.saveIpIntelligenceList(item);
        await appService.ipIntelligenceService.listService.saveListStatus(item, status);


        //prepare ips
        item.id = id;//set it back
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "1.1.1.1\n192.168.0.0/24\n9.8.8.8\n8.8.8.8\n3.3.3.3");
        await appService.ipIntelligenceService.listService.saveListFile(item, tmpFolderFile);
        //process
        await appService.ipIntelligenceService.listService.process(item);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/ip/intelligence/list/${item.id}/file`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.type).to.equal('application/octet-stream');



    }).timeout(50000);











})



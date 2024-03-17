
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Network } from '../src/model/network';


import { ESService } from '../src/service/esService';
import { ExpressApp } from '../src';
import { FqdnIntelligenceList, FqdnIntelligenceListStatus, FqdnIntelligenceSource } from '../src/model/fqdnIntelligence';
import { esHost, esPass, esUser } from './common.spec';


chai.use(chaiHttp);
const expect = chai.expect;


function expectToDeepEqual(a: any, b: any) {
    delete a.insertDate;
    delete a.updateDate;
    delete b.insertDate;
    delete b.updateDate;
    delete a.id;
    delete b.id;
    expect(a).to.deep.equal(b);
}




/**
 * authenticated user api tests
 */
describe('fqdnIntelligenceApi', async () => {
    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;
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
        await expressApp.start();
        await appService.configService.setConfigPath('/tmp/rest.portal.config.yaml');
        await appService.configService.init();
        await appService.configService.setIsConfigured(1);
        await appService.esService.reConfigure(esHost, esUser, esPass, '1s');

    })


    beforeEach(async () => {
        appService.configService.config.users = [];
        appService.configService.config.networks = [];
        appService.configService.config.gateways = [];
        appService.configService.config.fqdnIntelligence.sources = [];
        appService.configService.config.fqdnIntelligence.lists = [];
        await redisService.flushAll();
        await appService.esService.reset();
    })
    after(async () => {
        await expressApp.stop();
    })


    it('check authoration as admin role', async () => {
        //prepare data
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: FqdnIntelligenceSource = {
            id: Util.randomNumberString(),
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveFqdnIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/fqdn/intelligence/source`)
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




    //// fqdn intelligence source 

    it('GET /fqdn/intelligence/source will return items', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: FqdnIntelligenceSource = {
            id: Util.randomNumberString(),
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveFqdnIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/fqdn/intelligence/source`)
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

    it('DELETE /fqdn/intelligence/source', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: FqdnIntelligenceSource = {
            id: Util.randomNumberString(),
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveFqdnIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/api/fqdn/intelligence/source/` + item.id)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        const items = await appService.configService.getFqdnIntelligenceSources();
        expect(items.length).to.equal(0);


    }).timeout(50000);

    it('POST /fqdn/intelligence/source', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: FqdnIntelligenceSource = {
            id: Util.randomNumberString(), apiKey: 'abc',
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        //await appService.configService.saveFqdnIntelligenceSource(item);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/api/fqdn/intelligence/source`)
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

        const items = await appService.configService.getFqdnIntelligenceSources();
        expect(items.length).to.equal(1);


    }).timeout(50000);

    it('PUT /fqdn/intelligence/source', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')



        const item: FqdnIntelligenceSource = {
            id: Util.randomNumberString(), apiKey: 'abc',
            name: 'abc', type: 'acdf', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
        }

        await appService.configService.saveFqdnIntelligenceSource(item);
        item.apiKey = 'def'
        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/api/fqdn/intelligence/source`)
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

        const items = await appService.configService.getFqdnIntelligenceSources();
        expect(items.length).to.equal(1);
        expect(items[0].apiKey).to.equal('def');

    }).timeout(50000);



    it('GET /fqdn/intelligence/list will return items', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let id = Util.randomNumberString();
        const item: FqdnIntelligenceList = {
            id: id, labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt' }
        }
        const status: FqdnIntelligenceListStatus = {
            id: item.id
        }

        await appService.configService.saveFqdnIntelligenceList(item);
        await appService.fqdnIntelligenceService.listService.saveListStatus(item, status);

        // test all 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/fqdn/intelligence/list`)
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
                .get(`/api/fqdn/intelligence/list?search=te`)
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

        // test search fqdn
        //prepare fqdns
        item.id = id;//set it back
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\nferrumgate.com\ncom\nco.uk\nwww.facebook.com");
        await appService.fqdnIntelligenceService.listService.saveListFile(item, tmpFolderFile);
        //process
        await appService.fqdnIntelligenceService.listService.process(item);
        await Util.sleep(1000);

        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/fqdn/intelligence/list?search=ferrumgate.com`)
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


    it('PUT /fqdn/intelligence/list/id/reset will reset items', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let id = Util.randomNumberString();
        const item: FqdnIntelligenceList = {
            id: id, labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt' }
        }
        const status: FqdnIntelligenceListStatus = {
            id: item.id
        }

        await appService.configService.saveFqdnIntelligenceList(item);
        await appService.fqdnIntelligenceService.listService.saveListStatus(item, status);


        // test search fqdn
        //prepare fqdns
        item.id = id;//set it back
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\nferrumgate.com\ncom\nco.uk\nwww.facebook.com");
        await appService.fqdnIntelligenceService.listService.saveListFile(item, tmpFolderFile);
        //process
        await appService.fqdnIntelligenceService.listService.process(item);
        await Util.sleep(1000);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/fqdn/intelligence/list?search=com`)
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
                .put(`/api/fqdn/intelligence/list/${item.id}/reset`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);

        const result = await appService.fqdnIntelligenceService.listService.getByFqdn(item.id, 'ferrumgate.com')
        expect(result).not.exist;

        const result2 = await appService.fqdnIntelligenceService.listService.getListStatus(item);
        expect(result2).not.exist;
        const result3 = await appService.fqdnIntelligenceService.listService.getDbFileList(item);
        expect(Object.keys(result3 || {}).length == 0).to.be.true;


    }).timeout(50000);



    it('DELETE /fqdn/intelligence/list', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let id = Util.randomNumberString();
        const item: FqdnIntelligenceList = {
            id: id, labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt' }
        }
        const status: FqdnIntelligenceListStatus = {
            id: item.id
        }

        await appService.configService.saveFqdnIntelligenceList(item);
        await appService.fqdnIntelligenceService.listService.saveListStatus(item, status);


        //prepare fqdns
        item.id = id;//set it back
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\nferrumgate.com\ncom\nco.uk\nwww.facebook.com");
        await appService.fqdnIntelligenceService.listService.saveListFile(item, tmpFolderFile);
        //process
        await appService.fqdnIntelligenceService.listService.process(item);
        await Util.sleep(1000);

        // test all 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/api/fqdn/intelligence/list/${item.id}`)
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

        const result = await appService.configService.getFqdnIntelligenceList(id);
        expect(result).not.exist;
        const result2 = await appService.fqdnIntelligenceService.listService.getListStatus(item);
        expect(result2).not.exist;
        const listId = await appService.fqdnIntelligenceService.listService.getByFqdn(item.id, 'www.google.com')
        expect(listId).not.exist;



    }).timeout(50000);


    it('POST /fqdn/intelligence/list', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const filekey = Util.randomNumberString();

        const item: FqdnIntelligenceList = {
            id: '',
            labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt', key: filekey }
        }

        const tmpFolder = `/tmp/uploads`;

        fs.mkdirSync(tmpFolder, { recursive: true });
        const tmpFolderFile = `${tmpFolder}/${filekey}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\nferrumgate.com\ncom\nco.uk\nwww.facebook.com");

        // test all 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/api/fqdn/intelligence/list`)
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
        const savedItem = response.body as FqdnIntelligenceList;

        const result = await appService.configService.getFqdnIntelligenceList(savedItem.id);
        expect(result).exist;
        const result2 = await redisService.exists(`/intelligence/fqdn/list/${savedItem.id}/file`)
        expect(result2).to.be.true;




    }).timeout(50000);



    it('PUT /fqdn/intelligence/list', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const filekey = Util.randomNumberString();

        const item: FqdnIntelligenceList = {
            id: Util.randomNumberString(),
            labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt' }
        }

        const status: FqdnIntelligenceListStatus = {
            id: item.id
        }

        await appService.configService.saveFqdnIntelligenceList(item);
        await appService.fqdnIntelligenceService.listService.saveListStatus(item, status);

        const tmpFolder = `/tmp/uploads`;

        fs.mkdirSync(tmpFolder, { recursive: true });
        const tmpFolderFile = `${tmpFolder}/${filekey}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\nferrumgate.com\ncom\nco.uk\nwww.facebook.com");
        item.name = 'abo';
        if (item.file)
            item.file.key = filekey;
        // test all 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/api/fqdn/intelligence/list`)
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
        const savedItem = response.body as FqdnIntelligenceList;

        const result: FqdnIntelligenceList | undefined = await appService.configService.getFqdnIntelligenceList(savedItem.id);
        expect(result).exist;
        expect(result?.name).to.equal('abo');
        const result2 = await redisService.exists(`/intelligence/fqdn/list/${savedItem.id}/file`)
        expect(result2).to.be.true;




    }).timeout(50000);


    it('POST /fqdn/intelligence/list/file', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const tmpFolder = `/tmp/uploads`;

        fs.mkdirSync(tmpFolder, { recursive: true });
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\nferrumgate.com\ncom\nco.uk\nwww.facebook.com");

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/api/fqdn/intelligence/list/file`)
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


    it('GET /fqdn/intelligence/list/:id/file', async () => {
        //prepare data
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')


        let id = Util.randomNumberString();
        const item: FqdnIntelligenceList = {
            id: id, labels: ['test'],
            name: 'abc', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(), file: { source: 'test.txt' }
        }
        const status: FqdnIntelligenceListStatus = {
            id: item.id
        }

        await appService.configService.saveFqdnIntelligenceList(item);
        await appService.fqdnIntelligenceService.listService.saveListStatus(item, status);


        //prepare fqdn
        item.id = id;//set it back
        const tmpFolder = `/tmp/${Util.randomNumberString()}`;

        fs.mkdirSync(tmpFolder);
        const tmpFolderFile = `${tmpFolder}/${Util.randomNumberString()}`;
        fs.writeFileSync(tmpFolderFile, "www.google.com\nferrumgate.com\ncom\nco.uk\nwww.facebook.com");
        await appService.fqdnIntelligenceService.listService.saveListFile(item, tmpFolderFile);
        //process
        await appService.fqdnIntelligenceService.listService.process(item);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/api/fqdn/intelligence/list/${item.id}/file`)
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



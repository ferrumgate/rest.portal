
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { Network } from '../src/model/network';

import chaiExclude from 'chai-exclude';
import { IpIntelligence, IpIntelligenceList, IpIntelligenceListStatus, IpIntelligenceSource } from '../src/model/IpIntelligence';
import { ESService } from '../src/service/esService';
import { ExpressApp } from '../src';
import { SSLCertificate, SSLCertificateEx } from '../src/model/cert';



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
describe('pkiApi', async () => {
    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;
    const redisService = appService.redisService;
    const sessionService = appService.sessionService;
    const configService = appService.configService;
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


    })


    beforeEach(async () => {
        appService.configService.config.users = [];
        appService.configService.config.networks = [];
        appService.configService.config.gateways = [];
        appService.configService.config.ipIntelligence.sources = [];
        appService.configService.config.ipIntelligence.lists = [];
        appService.configService.config.inSSLCertificates = [];
        appService.configService.init();
        await redisService.flushAll();

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

        const item: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'abc', category: 'web', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true, labels: [],
        }



        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/pki/intermediate`)
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


    it('GET /pki/intermediate', async () => {


        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'abc', category: 'web', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true, labels: [],
        }
        await configService.saveInSSLCertificate(item);


        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/pki/intermediate`)
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
        expect(response.body.items.length).to.equal(4);

    }).timeout(50000);



    it('DELETE /pki/intermediate', async () => {


        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'abc', category: 'web', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true, labels: [],
        }

        await configService.saveInSSLCertificate(item);
        const certs = await configService.getInSSLCertificateAll();
        expect(certs.length).to.equal(4);

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/pki/intermediate/${certs.find(x => x.name == 'abc')?.id}`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        const certs2 = await configService.getInSSLCertificateAll();
        expect(certs2.length).to.equal(3);

    }).timeout(50000);



    it('PUT /pki/intermediate', async () => {


        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'abc', category: 'web', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true, labels: [],
            publicCrt: 'akey'
        }

        await configService.saveInSSLCertificate(item);
        item.publicCrt = 'change key';
        item.name = "aboo";

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/pki/intermediate`)
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
        //private key must not exists
        expect(response.body.privateKey).not.exist;
        expect(response.body.name).to.equal('aboo');
        expect(response.body.publicCrt).to.equal('akey');
        const cert = await configService.getInSSLCertificate(item.id);
        expect(cert?.publicCrt).to.equal('akey');

        //system items cannot change

        const item2: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'abc3dasdfa', category: 'web', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true, labels: [],
            publicCrt: 'akey', isSystem: true
        }

        await configService.saveInSSLCertificate(item2);


        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/pki/intermediate`)
                .set(`Authorization`, `Bearer ${token}`)
                .send(item2)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(400);



    }).timeout(50000);



    it('POST /pki/intermediate', async () => {


        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: SSLCertificateEx = {
            id: Util.randomNumberString(),
            name: 'abc', category: 'web', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true, labels: [],
            publicCrt: 'akey'
        }


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post(`/pki/intermediate`)
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
        //private key must not exists
        expect(response.body.privateKey).not.exist;
        expect(response.body.name).to.equal('abc');
        expect(response.body.publicCrt).not.equal('akey');





    }).timeout(50000);




    it('GET /pki/cert/web', async () => {


        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        /* const item: SSLCertificate = {
            idEx: Util.randomNumberString(),
            name: 'abc', category: 'web', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true, labels: [], privateKey: 'adfaf', publicCrt: 'adfaf'
        }
        await configService.setWebSSLCertificate(item);
 */

        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get(`/pki/cert/web`)
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
        expect(response.body.items.length).to.equal(1);

    }).timeout(50000);



    it('DELETE /pki/cert/web', async () => {


        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        const item: SSLCertificate = {
            idEx: Util.randomNumberString(),
            name: 'abc', category: 'web', updateDate: new Date().toISOString(),
            insertDate: new Date().toISOString(),
            isEnabled: true, labels: [], privateKey: 'adfaf', publicCrt: 'adfaf'
        }
        await configService.setWebSSLCertificate(item);


        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete(`/pki/cert/web`)
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body).exist;
        expect(response.body.name).to.equal('Web');
        expect(response.body.publicCrt).not.equal('adfaf');

    }).timeout(50000);



    it('PUT /pki/cert/web', async () => {


        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')





        // test search 
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/pki/cert/web`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ idEx: 'ab', name: 'test', publicCrt: 'akey', privateKey: 'de' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        //private key must not exists
        expect(response.body.privateKey).not.exist;
        expect(response.body.name).to.equal('test');
        expect(response.body.publicCrt).to.equal('akey');
        const cert = await configService.getWebSSLCertificateSensitive();
        expect(cert.publicCrt).to.equal('akey');
        expect(cert.privateKey).to.equal('de');





        //certs not changed
        response = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put(`/pki/cert/web`)
                .set(`Authorization`, `Bearer ${token}`)
                .send({ idEx: 'ab', name: 'test2', })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        //private key must not exists
        expect(response.body.privateKey).not.exist;
        expect(response.body.name).to.equal('test2');
        expect(response.body.publicCrt).to.equal('akey');
        const cert2 = await configService.getWebSSLCertificateSensitive();
        expect(cert2.publicCrt).to.equal('akey');
        expect(cert2.privateKey).to.equal('de');




    }).timeout(50000);










})



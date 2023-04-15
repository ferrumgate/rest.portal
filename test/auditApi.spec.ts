
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';

import { Util } from '../src/util';
import { Network } from '../src/model/network';
import { Gateway } from '../src/model/network';
import { AuditLog } from '../src/model/auditLog';
import { ESService } from '../src/service/esService';
import { ExpressApp } from '../src';

chai.use(chaiHttp);
const expect = chai.expect;


const esHost = 'https://192.168.88.250:9200';
const esUser = "elastic";
const esPass = '123456';

describe('auditApi ', async () => {
    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;
    const redisService = appService.redisService;
    const configService = appService.configService;
    const sessionService = appService.sessionService;


    before(async () => {
        await expressApp.start();
        if (fs.existsSync('/tmp/config.yaml'))
            fs.rmSync('/tmp/config.yaml')
        await configService.setConfigPath('/tmp/config.yaml');
        await configService.init();


    })

    beforeEach(async () => {
        await redisService.flushAll();
        configService.config.users = [
            {
                username: 'admin',
                groupIds: [],
                id: 'admin',
                name: 'admin',
                source: 'local',
                roleIds: ['Admin'],
                isLocked: false, isVerified: true,
                password: Util.bcryptHash('ferrumgate'),
                insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString()
            },
            {
                username: 'admin2',
                groupIds: [],
                id: 'admin2',
                name: 'admin2',
                source: 'local',
                roleIds: ['User'],
                isLocked: false, isVerified: true,
                password: Util.bcryptHash('ferrumgate'),
                insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString()
            }
        ];

    })
    after(async () => {
        await expressApp.stop();
    })
    it('only admin user can callit', async () => {
        const session = await sessionService.createSession({ id: 'admin2' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin2', sid: session.id }, 'ferrum')
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/log/audit')
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

    const host = 'https://192.168.88.250:9200';
    const user = 'elastic';
    const pass = '123456';

    function createSampleData2() {
        let audit1: AuditLog = {
            insertDate: new Date(2021, 1, 1).toISOString(),
            ip: '1.2.3.4',
            message: 'service deleted',
            messageDetail: 'mysqldev id >> abc',
            messageSummary: 'mysqldef',
            severity: 'warn',
            tags: 'a1a03923',
            userId: '3y0mt1634lp1',
            username: 'test@test.com'
        }
        let audit2: AuditLog = {
            insertDate: new Date(2021, 12, 31).toISOString(),
            ip: '1.2.3.4',
            message: 'service deleted',
            messageDetail: 'mysqlprod id >> abc',
            messageSummary: 'mysqlprod',
            severity: 'warn',
            tags: 'mypra1a03923',
            userId: '3y0mt1634lp1',
            username: 'test2@test.com'
        }
        let audit3: AuditLog = {
            insertDate: new Date().toISOString(),
            ip: '1.2.3.5',
            message: 'gateway deleted',
            messageDetail: 'mysqldev id >> abc',
            messageSummary: 'mysqldef',
            severity: 'warn',
            tags: 'a1a03923',
            userId: '3y0mt1634lp1',
            username: 'test@test.com'
        }
        return { audit1, audit2, audit3 }
    };

    it('/log/audit', async () => {

        const es = new ESService(configService, host, user, pass);
        await Util.sleep(1000);//wait for connecting
        await es.reset();
        const { audit1, audit2, audit3 } = createSampleData2();
        let data = await es.auditCreateIndexIfNotExits(audit1);
        await es.auditSave([data]);
        data = await es.auditCreateIndexIfNotExits(audit2);
        await es.auditSave([data]);
        data = await es.auditCreateIndexIfNotExits(audit3);
        await es.auditSave([data]);
        await es.flush();
        let test = 60000;
        while (test) {
            //check 
            const items = await es.searchAuditLogs({});
            if (items.total)
                break;
            test -= 5000;
            await Util.sleep(5000);
        }

        await appService.reconfigureES();
        const session = await sessionService.createSession({ id: 'admin' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin', sid: session.id }, 'ferrum');

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/log/audit')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response.status).to.equal(200);
        expect(response.body.total).to.equal(1);


    }).timeout(120000);




})



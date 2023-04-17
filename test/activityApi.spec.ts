
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { Util } from '../src/util';
import { Network } from '../src/model/network';
import { Gateway } from '../src/model/network';
import { AuditLog } from '../src/model/auditLog';
import { ESService } from '../src/service/esService';
import { ActivityLog } from '../src/model/activityLog';
import { ConfigService } from '../src/service/configService';
import { config } from 'process';
import { ExpressApp } from '../src';

chai.use(chaiHttp);
const expect = chai.expect;




describe('activityApi ', async () => {
    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;

    const redisService = appService.redisService;
    const configService = appService.configService;
    const sessionService = appService.sessionService;

    const host = 'https://192.168.88.250:9200';
    const user = 'elastic';
    const pass = '123456';



    before(async () => {

        await expressApp.start();
        if (fs.existsSync('/tmp/config.yaml'))
            fs.rmSync('/tmp/config.yaml')
        await configService.setConfigPath('/tmp/config.yaml');
        await configService.init();
        await configService.setES({ host: host, user: user, pass: pass })

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
            },
            {
                username: 'reporter3',
                groupIds: [],
                id: 'reporter3',
                name: 'reporter3',
                source: 'local',
                roleIds: ['Reporter'],
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
    it('only admin or reporter user can callit', async () => {
        const session = await sessionService.createSession({ id: 'admin2' } as any, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'admin2', sid: session.id }, 'ferrum')
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/insight/activity')
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





    function createSampleData2() {
        let activity1: ActivityLog = {
            insertDate: new Date().toISOString(),
            authSource: 'local',
            ip: '1.2.3.4',
            requestId: '123456',
            status: 0,
            statusMessage: 'SUCCESS',
            type: 'login try',
            sessionId: 's1',
            username: 'abc'
        }
        let activity2: ActivityLog = {
            insertDate: new Date(2021, 1.2).toISOString(),
            authSource: 'activedirectory',
            ip: '1.2.3.5',
            requestId: '1234567',
            status: 401,
            statusMessage: 'ERRAUTH',
            type: 'login 2fa',
            sessionId: 's1',
            username: 'abc@def',
            is2FA: true
        }
        return { activity1, activity2 }
    };

    it('/log/audit', async () => {

        const es = new ESService(configService, host, user, pass);
        await es.reset();
        const { activity1, activity2 } = createSampleData2();
        let data = await es.activityCreateIndexIfNotExits(activity1);
        await es.activitySave([data]);
        data = await es.activityCreateIndexIfNotExits(activity2);
        await es.activitySave([data]);

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
                .get('/insight/activity')
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

        //check reporter user

        const session2 = await sessionService.createSession({ id: 'reporter3' } as any, false, '1.1.1.1', 'local');
        const token2 = await appService.oauth2Service.generateAccessToken({ id: 'web', grants: [] }, { id: 'reporter3', sid: session2.id }, 'ferrum');

        let response2: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/insight/activity')
                .set(`Authorization`, `Bearer ${token2}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })
        expect(response2.status).to.equal(200);
        expect(response2.body.total).to.equal(1);


    }).timeout(120000);




})



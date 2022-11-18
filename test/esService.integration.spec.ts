
import chai from 'chai';
import chaiHttp from 'chai-http';
import * as odiff from 'deep-object-diff'
import { RedisService } from '../src/service/redisService';
import { AuditService, ObjectDiffer } from '../src/service/auditService';
import { AuditLog } from '../src/model/auditLog';
import { Util } from '../src/util';
import { ESService, SearchAuditLogsRequest } from '../src/service/esService';
import { ActivityLog } from '../src/model/activityLog';



chai.use(chaiHttp);
const expect = chai.expect;




describe('esService ', async () => {

    beforeEach(async () => {
        const es = new ESService(host, user, pass);
        await es.reset();
    })
    const host = 'https://192.168.88.250:9200';
    const user = 'elastic';
    const pass = '123456';
    /*     function createSampleData() {
            let audit: AuditLog = {
                insertDate: new Date().toISOString(),
                ip: '1.2.3.4',
                message: 'a messsage',
                messageDetail: 'message detail',
                messageSummary: 'message summary',
                severity: 'warn',
                tags: 'one two three',
                userId: '3y0mt1634lp1',
                username: '7ivraxcbah3g'
            }
            return { log1: audit }
        }
        it('auditCreateIndexIfNotExits', async () => {
            const es = new ESService(host, user, pass);
            const { log1 } = createSampleData();
            await es.auditCreateIndexIfNotExits(log1);
    
        }).timeout(15000);
    
        it('auditSave', async () => {
            const es = new ESService(host, user, pass);
            const { log1 } = createSampleData();
            const data = await es.auditCreateIndexIfNotExits(log1);
            await es.auditSave([data]);
    
        }).timeout(15000);
    
        it('getAllIndexes', async () => {
            const es = new ESService(host, user, pass);
            const { log1 } = createSampleData();
            const data = await es.auditCreateIndexIfNotExits(log1);
            await es.auditSave([data]);
            const indexes = await es.getAllIndexes();
            expect(indexes.length).to.equal(1);
    
        }).timeout(15000);
        it('reset', async () => {
            const es = new ESService(host, user, pass);
            const { log1 } = createSampleData();
            const data = await es.auditCreateIndexIfNotExits(log1);
            await es.auditSave([data]);
            const indexes = await es.getAllIndexes();
            expect(indexes.length).to.equal(1);
            await es.reset();
            const indexes2 = await es.getAllIndexes();
            expect(indexes2.length).to.equal(0);
    
        }).timeout(15000);
    
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
    
        it('searchAuditLogs', async () => {
            const es = new ESService(host, user, pass);
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
    
            //startDate?: string, endDate?: string, search?: string, users?: string, types?: string, page?: number, pageSize?: number
            let req: SearchAuditLogsRequest = { startDate: new Date(1, 1, 1).toISOString(), endDate: new Date().toISOString() }
            const items = await es.searchAuditLogs(req);
            expect(items.total).to.equal(3);
            expect(items.items.length).to.equal(3);
            //check date works
            req = { endDate: new Date().toISOString() }
            const items2 = await es.searchAuditLogs(req);
            expect(items2.total).to.equal(1);
            expect(items2.items.length).to.equal(1);
    
            //chec user works
            req = { startDate: new Date(1, 1, 1).toISOString(), endDate: new Date().toISOString(), username: 'test@test.com' }
            const items3 = await es.searchAuditLogs(req);
            expect(items3.total).to.equal(2);
            expect(items3.items.length).to.equal(2);
    
            req = { startDate: new Date(1, 1, 1).toISOString(), endDate: new Date().toISOString(), username: 'test@test.com,test2@test.com' }
            const items4 = await es.searchAuditLogs(req);
            expect(items4.total).to.equal(3);
            expect(items4.items.length).to.equal(3);
    
            //check types
            req = { startDate: new Date(1, 1, 1).toISOString(), endDate: new Date().toISOString(), message: 'service deleted' }
            const items5 = await es.searchAuditLogs(req);
            expect(items5.total).to.equal(2);
            expect(items5.items.length).to.equal(2);
    
    
            //search
            req = { startDate: new Date(1, 1, 1).toISOString(), endDate: new Date().toISOString(), search: 'mysqlprod' }
            const items6 = await es.searchAuditLogs(req);
            expect(items6.total).to.equal(1);
            expect(items6.items.length).to.equal(1);
    
    
    
        }).timeout(150000);
    
    */
    function createSampleData3() {
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
        return { activity1, activity2 };
    }

    it('activityCreateIndexIfNotExits', async () => {
        const es = new ESService(host, user, pass);
        const { activity1, activity2 } = createSampleData3();
        await es.activityCreateIndexIfNotExits(activity1);
        const indexes = await es.getAllIndexes();
        const fmt = es.dateFormat(activity1.insertDate)
        expect(indexes.includes(`ferrumgate-activity-${fmt}`));

    }).timeout(15000);

    it('activitySave', async () => {
        const es = new ESService(host, user, pass);
        const { activity1, activity2 } = createSampleData3();
        const data = await es.activityCreateIndexIfNotExits(activity1);
        await es.activitySave([data]);

    }).timeout(15000);


    it('activitySearch', async () => {
        const es = new ESService(host, user, pass);
        const { activity1, activity2 } = createSampleData3();
        const data = await es.activityCreateIndexIfNotExits(activity1);
        await es.activitySave([data]);
        const data2 = await es.activityCreateIndexIfNotExits(activity2);
        await es.activitySave([data2]);
        let test = 60000;//wait for es to flush
        while (test) {
            //check 
            const items = await es.searchActivityLogs({});
            if (items.total)
                break;
            test -= 5000;
            await Util.sleep(5000);
        }

        let items = await es.searchActivityLogs({ startDate: new Date(2020, 1, 1).toISOString() });
        expect(items.total).to.equal(2);

        items = await es.searchActivityLogs({ startDate: new Date(2020, 1, 1).toISOString(), requestId: '1234567' });
        expect(items.total).to.equal(1);

        items = await es.searchActivityLogs({ startDate: new Date(2020, 1, 1).toISOString(), type: activity1.type });
        expect(items.total).to.equal(1);

        items = await es.searchActivityLogs({ startDate: new Date(2020, 1, 1).toISOString(), status: 0 });
        expect(items.total).to.equal(1);

        items = await es.searchActivityLogs({ startDate: new Date(2020, 1, 1).toISOString(), is2FA: true });
        expect(items.total).to.equal(1);

        items = await es.searchActivityLogs({ startDate: new Date(2020, 1, 1).toISOString(), search: '123456' });
        expect(items.total).to.equal(1);




    }).timeout(120000);



})



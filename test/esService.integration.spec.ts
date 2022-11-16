
import chai from 'chai';
import chaiHttp from 'chai-http';
import * as odiff from 'deep-object-diff'
import { RedisService } from '../src/service/redisService';
import { AuditService, ObjectDiffer } from '../src/service/auditService';
import { AuditLog } from '../src/model/auditLog';
import { Util } from '../src/util';
import { ESService } from '../src/service/esService';



chai.use(chaiHttp);
const expect = chai.expect;




describe('esService ', async () => {

    beforeEach(async () => {

    })
    const host = 'https://192.168.88.250:9200';
    const user = 'elastic';
    const pass = '123456';
    function createSampleData() {
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
            const items = await es.searchAuditLogs();
            if (items.total)
                break;
            test -= 5000;
            await Util.sleep(5000);
        }

        const items = await es.searchAuditLogs(new Date(1, 1, 1).toISOString(), new Date().toISOString());
        expect(items.total).to.equal(3);
        expect(items.items.length).to.equal(3);
        //check date works
        const items2 = await es.searchAuditLogs(undefined, new Date().toISOString());
        expect(items2.total).to.equal(1);
        expect(items2.items.length).to.equal(1);

        //chec user works
        const items3 = await es.searchAuditLogs(new Date(1, 1, 1).toISOString(), new Date().toISOString(),
            undefined, 'test@test.com'
        );
        expect(items3.total).to.equal(2);
        expect(items3.items.length).to.equal(2);

        const items4 = await es.searchAuditLogs(new Date(1, 1, 1).toISOString(), new Date().toISOString(),
            undefined, 'test@test.com,test2@test.com'
        );
        expect(items4.total).to.equal(3);
        expect(items4.items.length).to.equal(3);

        //check types
        const items5 = await es.searchAuditLogs(new Date(1, 1, 1).toISOString(), new Date().toISOString(),
            undefined, undefined, 'service deleted'
        );
        expect(items5.total).to.equal(2);
        expect(items5.items.length).to.equal(2);


        //search
        const items6 = await es.searchAuditLogs(new Date(1, 1, 1).toISOString(), new Date().toISOString(),
            'mysqlprod', undefined, undefined,
        );
        expect(items6.total).to.equal(1);
        expect(items6.items.length).to.equal(1);



    }).timeout(150000);



})



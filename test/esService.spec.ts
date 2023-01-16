
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




describe.skip('esService ', async () => {

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




    function createSampleData4() {
        let activity1: ActivityLog = {
            "requestId": "nPvMKlEQ4nufB5MsU8Xg7RZCrthkUUefbFhvs99BgGq89IcZSUs48LfyS24cFnWU",
            "type": "login try",
            "username": "DdRMKfJvA2HG2eibzoJPcj4SkDw5ThR5dSIWjYra2fbipj0XmGOpQeAuPrmbcOar",
            "authSource": "tunnelKey",
            "insertDate": "2022-12-03T12:55:02.396Z",
            "ip": "172.18.0.7",
            "status": 401,
            "requestPath": "/alive",
            "statusMessage": "ErrNotAuthenticated"
        }
        let activity2: ActivityLog = {
            "requestId": "VkUmVlPqmPcalXrm6QmrchdKeLKPxQKDSev1gpL6WbVwuXHG2yfkoP6VVLsbzcxN",
            "type": "login try",
            "username": "9c13e48c6a2594475ec08ef761a6a04c5e4159e6bb769e95ecdf66f89d2e4f22b0981f57a459a5a7bb9a2ca4a7cce7bfadb7e64edfb6b86e690a31ce8cedd5e5d43db9dcafbb9074d00bc096e06ca8b28f37004f758d1710df00f5c237e60e1f23b6db4e8b28201f13292dab0ab7f7cab8ec4398daea4ac06e5af7c0724983de929150fe4826613dca36056418befa02",
            "authSource": "exchangeKey",
            "insertDate": "2022-12-03T11:52:08.215Z",
            "ip": "127.0.0.1",
            "status": 401,
            "requestPath": "/exchangetoken",
            "statusMessage": "ErrNotFound"
        }

        let activity3: ActivityLog = {
            "requestId": "WontUXiNgeyp6WSaZTPDYbr0rcZhqhQ8OoAUUyGTW8cKIkM86MK0YxufqolyiMkp",
            "type": "login try",
            "username": "hamza@hamzakilic.com",
            "authSource": "local",
            "insertDate": "2022-12-03T11:28:20.685Z",
            "ip": "127.0.0.1",
            "status": 401,
            "requestPath": "/",
            "statusMessage": "ErrNotAuthenticated"
        }
        let activity4: ActivityLog = {
            "requestId": "WontUXiNgeyp6WSaZTPDYbr0rcZhqhQ8OoAUUyGTW8cKIkM86MK0YxufqolyiMkp",
            "type": "login try",
            "username": "hamza@hamzakilic.com",
            "authSource": "local",
            "insertDate": "2022-12-03T11:28:20.685Z",
            "ip": "127.0.0.1",
            "status": 200,
            "requestPath": "/",
            "statusMessage": ""
        }
        return { activity1, activity2, activity3, activity4 };
    }

    function dayBefore(hour: number, start?: Date) {
        let s = start || new Date();
        return new Date(s.getTime() - hour * 60 * 60 * 1000);
    }

    it('getSummaryLoginTry', async () => {
        /*  const host = 'http://192.168.88.51:9200';
         const user = 'elastic';
         const pass = 'ux4eyrkbr47z6sckyf9zmavvgzxgvrzebsh082dumfk59j3b5ti9fvy95s7sybmx'; */
        const es = new ESService(host, user, pass);
        //let items2 = await es.getSummaryLoginTry({});
        const { activity1, activity2, activity3, activity4 } = createSampleData4();
        activity1.insertDate = dayBefore(24, new Date()).toISOString();
        activity2.insertDate = dayBefore(24 * 2, new Date()).toISOString();
        activity3.insertDate = dayBefore(24 * 3, new Date()).toISOString();
        activity4.insertDate = dayBefore(24 * 4, new Date()).toISOString();

        const data = await es.activityCreateIndexIfNotExits(activity1);
        await es.activitySave([data]);
        const data2 = await es.activityCreateIndexIfNotExits(activity2);
        await es.activitySave([data2]);
        const data3 = await es.activityCreateIndexIfNotExits(activity3);
        await es.activitySave([data3]);
        const data4 = await es.activityCreateIndexIfNotExits(activity4);
        await es.activitySave([data4]);
        let test = 60000;//wait for es to flush
        while (test) {
            //check 
            const items = await es.searchActivityLogs({});
            if (items.total)
                break;
            test -= 5000;
            await Util.sleep(5000);
        }

        let items = await es.getSummaryLoginTry({});
        expect(items.total).to.equal(3);
        expect(items.aggs.length).to.equal(7);
        expect(items.aggs[4].sub?.length).to.equal(1);




    }).timeout(120000);



    function createSampleData5() {
        let activity1: ActivityLog = {
            "requestId": "4FBday56qSKrTdxctpHl8h942vFsdG8VCwGqz0P0tbX0BghNyP7gxmapYG2Hy3GV",
            "type": "create tunnel",
            "username": "hamza@hamzakilic.com",
            "userId": "efnD8OvDcIQ9l4L0",
            "user2FA": false,
            "authSource": "local",
            "insertDate": "2022-12-03T19:37:01.513Z",
            "ip": "172.18.0.6",
            "status": 200,
            "sessionId": "ouKaeKqTT7v4vCTuduqYVW0nWugbs22sgfKrB3yDBRQSOVp9Hr6kivuY6emMl5Yy",
            "requestPath": "/",
            "assignedIp": "100.64.0.1",
            "tunnelId": "532gb5N4ORQArOaaxTPUfrXmZmPEWEWkSDVlc4DpY0jjPJ2KT53TfkmgIXSbQcz0",
            "tunType": "ssh",
            "trackId": 1,
            "gatewayId": "4s6ro4xte8009p96",
            "authnRuleId": "TzNauO9iacb9GEv7",
            "authnRuleName": "test"
        }

        return { activity1 };
    }



    it('getSummaryCreateTunnel', async () => {
        /* const host = 'http://192.168.88.51:9200';
        const user = 'elastic';
        const pass = 'ux4eyrkbr47z6sckyf9zmavvgzxgvrzebsh082dumfk59j3b5ti9fvy95s7sybmx'; */
        const es = new ESService(host, user, pass);

        const { activity1 } = createSampleData5();
        activity1.insertDate = dayBefore(24, new Date()).toISOString();

        const data = await es.activityCreateIndexIfNotExits(activity1);
        await es.activitySave([data]);

        let test = 60000;//wait for es to flush
        while (test) {
            //check 
            const items = await es.searchActivityLogs({});
            if (items.total)
                break;
            test -= 5000;
            await Util.sleep(5000);
        }

        let items = await es.getSummaryCreateTunnel({});
        expect(items.total).to.equal(1);
        expect(items.aggs.length).to.equal(7);
        expect(items.aggs[5].sub?.length).to.equal(1);

    }).timeout(120000);



    function createSampleData6() {
        let activity1: ActivityLog = {
            "requestId": "4FBday56qSKrTdxctpHl8h942vFsdG8VCwGqz0P0tbX0BghNyP7gxmapYG2Hy3GV",
            "type": "2fa check",
            "username": "hamza@hamzakilic.com",
            "userId": "efnD8OvDcIQ9l4L0",
            "user2FA": true,
            "authSource": "local",
            "insertDate": "2022-12-03T19:37:01.513Z",
            "ip": "172.18.0.6",
            "status": 200,
            "sessionId": "ouKaeKqTT7v4vCTuduqYVW0nWugbs22sgfKrB3yDBRQSOVp9Hr6kivuY6emMl5Yy",
            "requestPath": "/",
            "assignedIp": "100.64.0.1",
            "tunnelId": "532gb5N4ORQArOaaxTPUfrXmZmPEWEWkSDVlc4DpY0jjPJ2KT53TfkmgIXSbQcz0",
            "tunType": "ssh",
            "trackId": 1,
            "gatewayId": "4s6ro4xte8009p96",
            "authnRuleId": "TzNauO9iacb9GEv7",
            "authnRuleName": "test"
        }
        let activity2: ActivityLog = {
            "requestId": "4FBday56qSKrTdxctpHl8h942vFsdG8VCwGqz0P0tbX0BghNyP7gxmapYG2Hy3GV",
            "type": "2fa check",
            "username": "hamza@hamzakilic.com",
            "userId": "efnD8OvDcIQ9l4L0",
            "user2FA": true,
            "authSource": "local",
            "insertDate": "2022-12-03T19:37:01.513Z",
            "ip": "172.18.0.6",
            "status": 401,
            "sessionId": "ouKaeKqTT7v4vCTuduqYVW0nWugbs22sgfKrB3yDBRQSOVp9Hr6kivuY6emMl5Yy",
            "requestPath": "/",
            "assignedIp": "100.64.0.1",
            "tunnelId": "532gb5N4ORQArOaaxTPUfrXmZmPEWEWkSDVlc4DpY0jjPJ2KT53TfkmgIXSbQcz0",
            "tunType": "ssh",
            "trackId": 1,
            "gatewayId": "4s6ro4xte8009p96",
            "authnRuleId": "TzNauO9iacb9GEv7",
            "authnRuleName": "test"
        }

        return { activity1, activity2 };
    }



    it('getSummary2faCheck', async () => {
        /* const host = 'http://192.168.88.51:9200';
        const user = 'elastic';
        const pass = 'ux4eyrkbr47z6sckyf9zmavvgzxgvrzebsh082dumfk59j3b5ti9fvy95s7sybmx'; */
        const es = new ESService(host, user, pass);

        const { activity1, activity2 } = createSampleData6();
        activity1.insertDate = dayBefore(24, new Date()).toISOString();
        activity2.insertDate = dayBefore(48, new Date()).toISOString();


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

        let items = await es.getSummary2faCheck({});
        expect(items.total).to.equal(2);
        expect(items.aggs.length).to.equal(7);
        expect(items.aggs[4].sub?.length).to.equal(1);

    }).timeout(120000);




    function createSampleData7() {
        let activity1: ActivityLog = {
            "requestId": "4FBday56qSKrTdxctpHl8h942vFsdG8VCwGqz0P0tbX0BghNyP7gxmapYG2Hy3GV",
            "type": "login try",
            "username": "hamza@hamzakilic.com",
            "userId": "efnD8OvDcIQ9l4L0",
            "user2FA": true,
            "authSource": "local",
            "insertDate": "2022-12-03T19:37:01.513Z",
            "ip": "172.18.0.6",
            "status": 200,
            "sessionId": "ouKaeKqTT7v4vCTuduqYVW0nWugbs22sgfKrB3yDBRQSOVp9Hr6kivuY6emMl5Yy",
            "requestPath": "/",
            "assignedIp": "100.64.0.1",
            "tunnelId": "532gb5N4ORQArOaaxTPUfrXmZmPEWEWkSDVlc4DpY0jjPJ2KT53TfkmgIXSbQcz0",
            "tunType": "ssh",
            "trackId": 1,
            "gatewayId": "4s6ro4xte8009p96",
            "authnRuleId": "TzNauO9iacb9GEv7",
            "authnRuleName": "test"
        }
        let activity2: ActivityLog = {
            "requestId": "4FBday56qSKrTdxctpHl8h942vFsdG8VCwGqz0P0tbX0BghNyP7gxmapYG2Hy3GV",
            "type": "login try",
            "username": "admin@hamzakilic.com",
            "userId": "efnD8OsDcIQ9l4L0",
            "user2FA": true,
            "authSource": "local",
            "insertDate": "2022-12-03T19:37:01.513Z",
            "ip": "172.18.0.6",
            "status": 401,
            "sessionId": "ouKaeKqTT7v4vCTuduqYVW0nWugbs22sgfKrB3yDBRQSOVp9Hr6kivuY6emMl5Yy",
            "requestPath": "/",
            "assignedIp": "100.64.0.1",
            "tunnelId": "532gb5N4ORQArOaaxTPUfrXmZmPEWEWkSDVlc4DpY0jjPJ2KT53TfkmgIXSbQcz0",
            "tunType": "ssh",
            "trackId": 1,
            "gatewayId": "4s6ro4xte8009p96",
            "authnRuleId": "TzNauO9iacb9GEv7",
            "authnRuleName": "test"
        }

        return { activity1, activity2 };
    }


    it('getSummaryUserLoginSuccess', async () => {
        /* const host = 'http://192.168.88.51:9200';
        const user = 'elastic';
        const pass = 'ux4eyrkbr47z6sckyf9zmavvgzxgvrzebsh082dumfk59j3b5ti9fvy95s7sybmx'; */
        const es = new ESService(host, user, pass);

        const { activity1, activity2 } = createSampleData7();
        activity1.insertDate = dayBefore(24, new Date()).toISOString();
        activity2.insertDate = dayBefore(48, new Date()).toISOString();


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

        let items = await es.getSummaryUserLoginSuccess({});
        expect(items.total).to.equal(1);
        expect(items.aggs.length).to.equal(1);


    }).timeout(120000);

    it('getSummaryUserLoginFailed', async () => {
        /* const host = 'http://192.168.88.51:9200';
        const user = 'elastic';
        const pass = 'ux4eyrkbr47z6sckyf9zmavvgzxgvrzebsh082dumfk59j3b5ti9fvy95s7sybmx'; */
        const es = new ESService(host, user, pass);

        const { activity1, activity2 } = createSampleData7();
        activity1.insertDate = dayBefore(24, new Date()).toISOString();
        activity2.insertDate = dayBefore(48, new Date()).toISOString();


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

        let items = await es.getSummaryUserLoginFailed({});
        expect(items.total).to.equal(1);
        expect(items.aggs.length).to.equal(1);


    }).timeout(120000);


    it('getSummaryUserLoginTry', async () => {
        /*  const host = 'http://192.168.88.51:9200';
         const user = 'elastic';
         const pass = 'ux4eyrkbr47z6sckyf9zmavvgzxgvrzebsh082dumfk59j3b5ti9fvy95s7sybmx'; */
        const es = new ESService(host, user, pass);
        //let items2 = await es.getSummaryLoginTry({});
        const { activity1, activity2, activity3, activity4 } = createSampleData4();
        activity1.insertDate = dayBefore(24, new Date()).toISOString();
        activity2.insertDate = dayBefore(24 * 2, new Date()).toISOString();
        activity3.insertDate = dayBefore(24 * 3, new Date()).toISOString();
        activity4.insertDate = dayBefore(24 * 4, new Date()).toISOString();

        const data = await es.activityCreateIndexIfNotExits(activity1);
        await es.activitySave([data]);
        const data2 = await es.activityCreateIndexIfNotExits(activity2);
        await es.activitySave([data2]);
        const data3 = await es.activityCreateIndexIfNotExits(activity3);
        await es.activitySave([data3]);
        const data4 = await es.activityCreateIndexIfNotExits(activity4);
        await es.activitySave([data4]);
        let test = 60000;//wait for es to flush
        while (test) {
            //check 
            const items = await es.searchActivityLogs({});
            if (items.total)
                break;
            test -= 5000;
            await Util.sleep(5000);
        }

        let items = await es.getSummaryUserLoginTry({ username: "hamza@hamzakilic.com" });
        expect(items.total).to.equal(2);
        expect(items.aggs.length).to.equal(7);
        expect(items.aggs[2].sub?.length).to.equal(1);

    }).timeout(120000);


    it('getSummaryUserLoginTryHours', async () => {
        /*  const host = 'http://192.168.88.51:9200';
         const user = 'elastic';
         const pass = 'ux4eyrkbr47z6sckyf9zmavvgzxgvrzebsh082dumfk59j3b5ti9fvy95s7sybmx'; */
        const es = new ESService(host, user, pass);
        //let items2 = await es.getSummaryLoginTry({});
        const { activity1, activity2, activity3, activity4 } = createSampleData4();
        activity1.insertDate = dayBefore(24, new Date()).toISOString();
        activity2.insertDate = dayBefore(24 * 2, new Date()).toISOString();
        activity3.insertDate = dayBefore(24 * 3, new Date()).toISOString();
        activity4.insertDate = dayBefore(24 * 4, new Date()).toISOString();

        const data = await es.activityCreateIndexIfNotExits(activity1);
        await es.activitySave([data]);
        const data2 = await es.activityCreateIndexIfNotExits(activity2);
        await es.activitySave([data2]);
        const data3 = await es.activityCreateIndexIfNotExits(activity3);
        await es.activitySave([data3]);
        const data4 = await es.activityCreateIndexIfNotExits(activity4);
        await es.activitySave([data4]);
        let test = 60000;//wait for es to flush
        while (test) {
            //check 
            const items = await es.searchActivityLogs({});
            if (items.total)
                break;
            test -= 5000;
            await Util.sleep(5000);
        }

        let items = await es.getSummaryUserLoginTryHours({ username: "hamza@hamzakilic.com" });
        expect(items.total).to.equal(2);
        expect(items.aggs.length > 6 * 24).to.be.true;


    }).timeout(120000);





})



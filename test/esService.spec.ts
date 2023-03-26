
import chai from 'chai';
import chaiHttp from 'chai-http';
import * as odiff from 'deep-object-diff'
import { RedisService } from '../src/service/redisService';
import { AuditService, ObjectDiffer } from '../src/service/auditService';
import { AuditLog } from '../src/model/auditLog';
import { Util } from '../src/util';
import { ESService, SearchAuditLogsRequest } from '../src/service/esService';
import { ActivityLog } from '../src/model/activityLog';
import { ConfigService } from '../src/service/configService';
import { IpIntelligenceList, IpIntelligenceListItem } from '../src/model/IpIntelligence';



chai.use(chaiHttp);
const expect = chai.expect;




describe('esService ', async () => {
    const host = 'https://192.168.88.250:9200';
    const user = 'elastic';
    const pass = '123456';
    const config = new ConfigService('fljvc7rm1xfo37imbu3ryc5mfbh9jpm5', `/tmp/${Util.randomNumberString()}`)
    beforeEach(async () => {
        await config.setES({ host: host, user: user, pass: pass })
        try {
            const es = new ESService(config, host, user, pass, '1s');
            await es.reset();
        } catch (err) {

        }
    })


    /*     function createSampleData3() {
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
            const es = new ESService(config, host, user, pass, '1s');
            const { activity1, activity2 } = createSampleData3();
            await es.activityCreateIndexIfNotExits(activity1);
            const indexes = await es.getAllIndexes();
            const fmt = es.dateFormat(activity1.insertDate)
            expect(indexes.includes(`ferrumgate-activity-${fmt}`));
    
        }).timeout(15000);
    
        it('createIndex/Delete', async () => {
            const es = new ESService(config, host, user, pass, '1s');
            const { activity1, activity2 } = createSampleData3();
            await es.activityCreateIndexIfNotExits(activity1);
            const indexes = await es.getAllIndexes();
            const fmt = es.dateFormat(activity1.insertDate)
            expect(indexes.includes(`ferrumgate-activity-${fmt}`));
            await es.deleteIndexes(indexes);
            await Util.sleep(1000);
            const indexes2 = await es.getAllIndexes();
            expect(indexes2.length).to.equal(0);
    
    
        }).timeout(15000);
    
        it('activitySave', async () => {
            const es = new ESService(config, host, user, pass, '1s');
            const { activity1, activity2 } = createSampleData3();
            const data = await es.activityCreateIndexIfNotExits(activity1);
            await es.activitySave([data]);
    
        }).timeout(15000);
    
    
        it('activitySearch', async () => {
    
            const es = new ESService(config, host, user, pass, '1s');
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
    
            const es = new ESService(config, host, user, pass, '1s');
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
    
            const es = new ESService(config, host, user, pass, '1s');
    
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
    
            const es = new ESService(config, host, user, pass, '1s');
    
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
    
            const es = new ESService(config, host, user, pass, '1s');
    
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
    
            const es = new ESService(config, host, user, pass, '1s');
    
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
    
            const es = new ESService(config, host, user, pass, '1s');
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
    
            const es = new ESService(config, host, user, pass, '1s');
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
        it('reConfigure', async () => {
            const host = 'https://localhost:9500';
            const user = 'elastic';
            const pass = '123456';
            const es = new ESService(config, host, user, pass, '1s');
            const { activity1, activity2 } = createSampleData3();
            let isError = false;
            try {
                const data = await es.activityCreateIndexIfNotExits(activity1);
                await es.activitySave([data]);
            } catch (err) {
                isError = true;
            }
            expect(isError).to.be.true;
    
            await es.reConfigure('https://192.168.88.250:9200', user, pass);
            isError = false;
            try {
                const data = await es.activityCreateIndexIfNotExits(activity1);
                await es.activitySave([data]);
            } catch (err) {
                isError = true;
            }
            expect(isError).to.be.false;
    
        }).timeout(130000);
    
    
        it('reConfigure2 reconnect to same host', async () => {
            const host = 'https://192.168.88.250:9200';
            const user = 'elastic';
            const pass = '123456';
            const es = new ESService(config, host, user, pass, '1s');
            const { activity1, activity2 } = createSampleData3();
            let isError = false;
            try {
                const data = await es.activityCreateIndexIfNotExits(activity1);
                await es.activitySave([data]);
            } catch (err) {
                isError = true;
            }
            expect(isError).to.be.false;
    
            await es.reConfigure('https://192.168.88.250:9200', user, pass);
            isError = false;
            try {
                const data = await es.activityCreateIndexIfNotExits(activity1);
                await es.activitySave([data]);
            } catch (err) {
                isError = true;
            }
            expect(isError).to.be.false;
    
        }).timeout(130000);
     */


    // ip intelligence list 

    function createSampleData10() {
        let list: IpIntelligenceList = {
            id: Util.randomNumberString(), name: "test",
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),

        }
        let list1Item1: IpIntelligenceListItem = {
            insertDate: new Date().toISOString(),
            id: list.id, page: 5,
            network: '192.168.0.0/16'
        }
        let list1Item2: IpIntelligenceListItem = {
            insertDate: new Date().toISOString(),
            id: list.id, page: 5,
            network: '192.168.10.10/24'
        }
        let list1Item3: IpIntelligenceListItem = {
            insertDate: new Date().toISOString(),
            id: list.id, page: 6,
            network: '172.28.0.10/32'
        }

        let list2: IpIntelligenceList = {
            id: Util.randomNumberString(), name: "test",
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),

        }
        let list2Item1: IpIntelligenceListItem = {
            insertDate: new Date().toISOString(),
            id: list2.id, page: 5,
            network: '192.168.0.0/16'
        }
        let list2Item2: IpIntelligenceListItem = {
            insertDate: new Date().toISOString(),
            id: list2.id, page: 5,
            network: '192.168.10.10/24'
        }
        let list2Item3: IpIntelligenceListItem = {
            insertDate: new Date().toISOString(),
            id: list2.id, page: 6,
            network: '172.28.0.10/32'
        }

        return {
            list, list1Item1, list1Item2, list1Item3,
            list2, list2Item1, list2Item2, list2Item3
        }

    }

    it('ipIntellligenceListCreateIndexIfNotExits', async () => {
        const es = new ESService(config, host, user, pass, '1s');
        const {
            list, list1Item1, list1Item2, list1Item3,
            list2, list2Item1, list2Item2, list2Item3 } = createSampleData10();
        await es.ipIntelligenceListCreateIndexIfNotExits(list1Item1);
        await es.ipIntelligenceListCreateIndexIfNotExits(list2Item1);
        const indexes = await es.getAllIndexes();
        expect(indexes.includes(`ip-intelligence-list-${list.id}`));
        expect(indexes.includes(`ip-intelligence-list-${list2.id}`));

    }).timeout(15000);


    it('ipIntelligenceListSave', async () => {
        const es = new ESService(config, host, user, pass, '1s');
        const {
            list, list1Item1, list1Item2, list1Item3,
            list2, list2Item1, list2Item2, list2Item3 } = createSampleData10();
        const data = await es.ipIntelligenceListCreateIndexIfNotExits(list1Item1);
        await es.ipIntelligenceListItemSave([data]);

    }).timeout(15000);


    it('ipIntelligenceListSearch', async () => {

        const es = new ESService(config, host, user, pass, '1s');
        const {
            list, list1Item1, list1Item2, list1Item3,
            list2, list2Item1, list2Item2, list2Item3 } = createSampleData10();
        for (let item of [list1Item1, list1Item2, list1Item3, list2Item1, list2Item2, list2Item3]) {
            const data = await es.ipIntelligenceListCreateIndexIfNotExits(item);
            await es.ipIntelligenceListItemSave([data]);
        }
        let tryCounter = 10;
        let listIds;
        while (tryCounter--) {
            listIds = await es.searchIpIntelligenceList({ searchIp: '192.168.10.100' });
            if (listIds.items.length > 0)
                break;
            await Util.sleep(1000);
        }
        expect(listIds?.items.length == 2).to.be.true;



    }).timeout(120000);

    it('deleteIpIntelligenceList', async () => {

        const es = new ESService(config, host, user, pass, '1s');
        const {
            list, list1Item1, list1Item2, list1Item3,
            list2, list2Item1, list2Item2, list2Item3 } = createSampleData10();
        for (let item of [list1Item1, list1Item2, list1Item3, list2Item1, list2Item2, list2Item3]) {
            const data = await es.ipIntelligenceListCreateIndexIfNotExits(item);
            await es.ipIntelligenceListItemSave([data]);
        }
        await Util.sleep(1000);

        await es.deleteIpIntelligenceList({ page: 5, id: list.id });
        await Util.sleep(1000);

        let listIds = await es.searchIpIntelligenceList({ id: list.id, searchIp: '192.168.10.100' });
        expect(listIds.items.length).to.equal(0);

        //delete all idnex
        await es.deleteIpIntelligenceList({ id: list.id });
        await Util.sleep(1000);

        // 
        const indexes = await es.getAllIndexes();
        expect(indexes.includes(`ip-intelligence-list-${list.id.toLowerCase()}`)).to.be.false;



    }).timeout(120000);

    it('scrollIpIntelligenceList', async () => {

        const es = new ESService(config, host, user, pass, '1s');
        const {
            list, list1Item1, list1Item2, list1Item3,
            list2, list2Item1, list2Item2, list2Item3 } = createSampleData10();
        for (let item of [list1Item1, list1Item2, list1Item3, list2Item1, list2Item2, list2Item3]) {
            const data = await es.ipIntelligenceListCreateIndexIfNotExits(item);
            await es.ipIntelligenceListItemSave([data]);
        }
        await Util.sleep(1000);

        const items: IpIntelligenceListItem[] = [];
        await es.scrollIpIntelligenceList({ id: list.id }, () => true, async (el: any) => {
            items.push(el);
        })

        expect(items.length).to.equal(3);


    }).timeout(120000);






})



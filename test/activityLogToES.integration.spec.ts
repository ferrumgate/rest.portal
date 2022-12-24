
import chai from 'chai';
import chaiHttp from 'chai-http';
import * as odiff from 'deep-object-diff'
import { RedisService } from '../src/service/redisService';
import { AuditService, ObjectDiffer } from '../src/service/auditService';
import { AuditLog } from '../src/model/auditLog';
import { Util } from '../src/util';
import { ESService } from '../src/service/esService';
import { AuditLogToES } from '../src/service/system/auditLogToES';
import { ConfigService } from '../src/service/configService';
import { ActivityLog } from '../src/model/activityLog';
import { ActivityService } from '../src/service/activityService';
import { ActivityLogToES } from '../src/service/system/activityLogToES';
import { RedisWatcher } from '../src/service/system/redisWatcher';
import { watch } from 'fs';



chai.use(chaiHttp);
const expect = chai.expect;



const esHost = 'https://192.168.88.250:9200';
const esUser = "elastic";
const esPass = '123456';
describe('activityLogToES ', async () => {

    beforeEach(async () => {


    })


    const streamKey = '/logs/audit';
    function createSampleData() {
        const log1: ActivityLog = {
            insertDate: new Date().toISOString(),
            ip: '1.2.3.4',
            authSource: 'local', requestId: '123', status: 0,
            type: 'login try',
            userId: '12131a',
            username: 'abcda@email.com'
        }

        const log2: ActivityLog = {
            insertDate: new Date().toISOString(),
            ip: '1.2.3.5',
            authSource: 'activedirectory', requestId: '1234', status: 0,
            type: 'login try',
            userId: 'a12131a',
            username: 'aaabcda@email.com'
        }
        return { log1, log2 };
    }
    it('saveToES', async () => {
        class Mock extends ActivityLogToES {
            createESService(): ESService {
                return new ESService(esHost, esUser, esPass)
            }
        }
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        //first create a config and save to a file
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        const redis = new RedisService();
        await redis.flushAll();
        const es = new ESService(esHost, esUser, esPass);
        const { log1, log2 } = createSampleData();

        const activityService = new ActivityService(redis, es);
        await activityService.save(log1);
        await activityService.save(log2);

        await es.reset();
        const watcher = new RedisWatcher();
        await watcher.start();
        const activityLog = new Mock(configService, redis, watcher);
        await activityLog.start();
        await activityLog.stop();
        await Util.sleep(5000);
        /*  const result = await es.search({
             index: 'ferrumgate-activity', body: {
                 query: {
                     match_all: {}
                 }
             }
         }) */
        const redisPos = await redis.get('/logs/activity/pos', false);
        expect(redisPos).exist;


    }).timeout(200000);


})



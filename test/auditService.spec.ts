
import chai from 'chai';
import chaiHttp from 'chai-http';
import * as odiff from 'deep-object-diff'
import { RedisService } from '../src/service/redisService';
import { AuditService, ObjectDiffer } from '../src/service/auditService';
import { AuditLog } from '../src/model/auditLog';
import { Util } from '../src/util';
import { ESService } from '../src/service/esService';
import { ConfigService } from '../src/service/configService';



chai.use(chaiHttp);
const expect = chai.expect;




describe('auditService ', async () => {

    beforeEach(async () => {

    })
    it('object differ calculate', async () => {
        const removeProperties = ['id', 'password', 'secretKey', 'key'];
        let obj = { id: 1, name: 'aborted', gsm: 34, role: { name: 'acb' }, test: [1, 3, 4] };
        let obj2 = { id: 1, name: 'ab', surname: '22', role: { name: 'def', sur: 'xx' }, test: [1, 2, 3] };

        let y = odiff.detailedDiff(obj, obj2) as any;
        let x = odiff.diff(obj, obj2);
        const msg = ObjectDiffer.calculate(obj, obj2, removeProperties);
        const msgList: string[] = [];
        msg.forEach((value, key) => msgList.push(key + ': ' + value));
        const msgStr = msgList.join(',');
        expect(msgStr).to.equal('.added.surname: null >>> 22,.added.role.sur: null >>> xx,.deleted.gsm: 34 >>> null,.updated.name: aborted >>> ab,.updated.role.name: acb >>> def,.updated.test.1: 3 >>> 2,.updated.test.2: 4 >>> 3');



    }).timeout(5000);

    it('object differ calculate2', async () => {
        const removeProperties = ['id', 'password', 'secretKey', 'key'];
        let obj = { id: 1, name: 'aborted', gsm: 34, role: { name: 'acb' }, test: [1, 3, 4], ops: [{ id: 2, name: 'deneme' }, { id: 3, name: 'dea' }] };
        let obj2 = { id: 1, name: 'ab', surname: '22', role: { name: 'def', sur: 'xx' }, test: [1, 2, 3], ops: [{ id: 4, name: 'dea2' }] };

        let y = odiff.detailedDiff(obj, obj2) as any;
        let x = odiff.diff(obj, obj2);
        const msg = ObjectDiffer.calculate(obj, obj2, removeProperties);
        const msgList: string[] = [];
        msg.forEach((value, key) => msgList.push(key + ': ' + value));
        const msgStr = msgList.join(',');
        expect(msgStr).to.equal('.added.surname: null >>> 22,.added.role.sur: null >>> xx,.deleted.gsm: 34 >>> null,.deleted.ops.1: { .name: dea } >>> null,.updated.name: aborted >>> ab,.updated.role.name: acb >>> def,.updated.test.1: 3 >>> 2,.updated.test.2: 4 >>> 3,.updated.ops.0.name: deneme >>> dea2');
    })

    const streamKey = '/logs/audit';
    const esHost = 'https://192.168.88.250:9200';
    const esUser = "elastic";
    const esPass = '123456';
    const config = new ConfigService('fljvc7rm1xfo37imbu3ryc5mfbh9jpm5', `/tmp/${Util.randomNumberString()}`)
    it('saveToRedis', async () => {

        const es = new ESService(esHost, esUser, esPass);
        const redis = new RedisService();
        await redis.delete(streamKey)
        let audit = {
            id: 1
        } as any;
        const auditService = new AuditService(config, redis, es);
        await auditService.saveToRedis(audit);
        await Util.sleep(1000);
        const items = await redis.xread(streamKey, 10, '0', 1000);
        expect(items.length).to.equal(1);
        const item = items[0];
        const data = Util.jdecrypt(auditService.encKey, Buffer.from(item.val, 'base64url'));//  Util.decrypt(auditService.encKey, item.data, 'base64url');
        expect(data).exist;
        const obj = Util.jdecode(data);// JSON.parse(data);
        expect(obj).deep.equal(audit);
        await auditService.stop();


    }).timeout(20000);

    it('executeTryCatch', async () => {
        const es = new ESService(esHost, esUser, esPass)
        const redis = new RedisService();
        const auditService = new AuditService(config, redis, es);
        //expect no error 
        await auditService.executeTryCatch(async () => {
            throw new Error('this is will be ignored')
        })
        await auditService.stop();


    }).timeout(20000);

    it('executeDelete', async () => {
        const es = new ESService(esHost, esUser, esPass)
        const redis = new RedisService();
        await redis.delete(streamKey)
        let before = {
            id: 1,
            name: 'test',
            city: 'london'
        } as any;
        let after = {
            id: 1,
            name: 'test',
            city: 'singapore'
        } as any;

        const auditService = new AuditService(config, redis, es);
        await auditService.executeDelete(
            { ip: '1.2.3.4' } as any,
            { id: 'someid', username: 'auser' } as any,
            before, 'user deleted', 'username');


        await Util.sleep(1000);
        const items = await redis.xread(streamKey, 10, '0', 1000);
        expect(items.length).to.equal(1);
        const item = items[0];
        const data = Util.jdecrypt(auditService.encKey, Buffer.from(item.val, 'base64url'));;// Util.decrypt(auditService.encKey, item.data, 'base64url');
        expect(data).exist;
        const obj = Util.jdecode(data) as any;// JSON.parse(data);
        expect(obj.ip).to.equal('1.2.3.4');
        expect(obj.insertDate).exist;
        expect(obj.userId).to.equal('someid');
        expect(obj.username).to.equal('auser');
        expect(obj.message).to.equal('user deleted');
        expect(obj.messageSummary).to.equal('username');
        expect(obj.messageDetail).exist;
        expect(obj.tags).exist;
        await auditService.stop();


    }).timeout(20000);

    it('executeSave', async () => {
        const es = new ESService(esHost, esUser, esPass)
        const redis = new RedisService();
        await redis.delete(streamKey)
        let before = {
            id: 1,
            name: 'test',
            city: 'london'
        } as any;
        let after = {
            id: 1,
            name: 'test',
            city: 'singapore'
        } as any;

        const auditService = new AuditService(config, redis, es);
        await auditService.executeSave(
            { ip: '1.2.3.4' } as any,
            { id: 'someid', username: 'auser' } as any,
            before, after, 'user updated', 'username');


        await Util.sleep(1000);
        const items = await redis.xread(streamKey, 10, '0', 1000);
        expect(items.length).to.equal(1);
        const item = items[0];
        const data = Util.jdecrypt(auditService.encKey, Buffer.from(item.val, 'base64url'));;;//  Util.decrypt(auditService.encKey, item.data, 'base64url');
        expect(data).exist;
        const obj = Util.jdecode(data) as any;// JSON.parse(data);
        expect(obj.ip).to.equal('1.2.3.4');
        expect(obj.insertDate).exist;
        expect(obj.userId).to.equal('someid');
        expect(obj.username).to.equal('auser');
        expect(obj.message).to.equal('user updated');
        expect(obj.messageSummary).to.equal('username');
        expect(obj.messageDetail).exist;
        expect(obj.tags).exist;
        await auditService.stop();


    }).timeout(20000);












})



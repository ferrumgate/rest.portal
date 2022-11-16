
//docker run --net=host --name redis --rm -d redis


import chai from 'chai';
import chaiHttp from 'chai-http';
import { Util } from '../src/util';
import { RedisService, RedisServiceManuel } from '../src/service/redisService';
import cryp from 'crypto';



chai.use(chaiHttp);
const expect = chai.expect;


describe('redisService', () => {
    beforeEach(async () => {
        const simpleRedis = new RedisService('localhost:6379,localhost:6390');
        await simpleRedis.flushAll();
    })

    it('test add remove get', async () => {
        const simpleRedis = new RedisService('localhost:6379,localhost:6390');

        await simpleRedis.set('deneme', 'deneme', { ttl: '15000' });
        let data = await simpleRedis.get<string>('deneme', false);
        expect(data).to.equal('deneme');


        let contains = await simpleRedis.containsKey('deneme');
        expect(contains).to.be.true;
        for (let i = 0; i < 1000; ++i) {
            try {
                await simpleRedis.set('deneme2', 'deneme', { ttl: '30000' });
                let contains2 = await simpleRedis.containsKey('deneme2');
                expect(contains2).to.be.true;

                await simpleRedis.remove('deneme2');
                let contains3 = await simpleRedis.containsKey('deneme2');
                expect(contains3).to.be.false;

            } catch (errr) {

            }

        }



    }).timeout(10000)

    it('test transaction', async () => {
        const simpleRedis = new RedisService('localhost:6379');

        let pipe = await simpleRedis.multi()
        await pipe.set('deneme2', 'deneme2', { ttl: '60000' });
        await pipe.get('deneme2')
        let results = await pipe.exec();
        let as = await simpleRedis.get('deneme2', false)

        expect(as).to.equal('deneme2');



    }).timeout(10000)

    it('test transaction that will be null and set other', async () => {
        const simpleRedis = new RedisService('localhost:6379');


        let pipe = await simpleRedis.multi()
        await pipe.set('deneme3', 'deneme3', { ttl: '60000' });
        await pipe.get('deneme3')
        //let results=await pipe.exec();
        let as = await simpleRedis.get('deneme3', false)

        expect(as).to.be.null
        pipe = await simpleRedis.multi()
        await pipe.set('deneme4', 'deneme4', { ttl: '60000' });
        await pipe.get('deneme4')
        let results = await pipe.exec();
        as = await simpleRedis.get('deneme4', false)
        expect(as).to.equal('deneme4');



    }).timeout(10000)


    it('test transaction that will terminate transaction', async () => {
        const simpleRedis = new RedisService('localhost:6379');

        for (let i = 0; i < 1000; ++i) {
            let pipe = await simpleRedis.multi()
            await pipe.set('deneme30', 'deneme30', { ttl: '60000' });
            await pipe.get('deneme30')
            //let results=await pipe.exec();
            let as = await simpleRedis.get('deneme30', false)

            expect(as).to.be.null
        }




    }).timeout(10000)


    it('redis set object', async () => {

        const simpleRedis = new RedisService('localhost:6379');
        let obj = { ttl: 10 };
        await simpleRedis.set('test', obj);
        let retObj = await simpleRedis.get('test') as any;
        expect(retObj).not.null;
        expect(retObj.ttl).to.equal(10);

        await simpleRedis.set('test', obj, { ttl: 10000 });
        retObj = await simpleRedis.get('test', true) as any;
        expect(retObj).not.null;
        expect(retObj.ttl).to.equal(10);

        let pipe = await simpleRedis.multi();
        await pipe.set('test', obj);
        await pipe.exec();
        retObj = await simpleRedis.get('test') as any;
        expect(retObj).not.null;
        expect(retObj.ttl).to.equal(10);

        pipe = await simpleRedis.multi();
        await pipe.set('test', obj, { ttl: 10000 });
        await pipe.exec();
        retObj = await simpleRedis.get('test') as any;
        expect(retObj).not.null;
        expect(retObj.ttl).to.equal(10);





    }).timeout(10000)

    it('redis set number', async () => {

        const simpleRedis = new RedisService('localhost:6379');
        let obj = { ttl: 10 };
        await simpleRedis.set('test', 10);
        let retObj = await simpleRedis.get('test') as any;
        expect(retObj).not.null;
        expect(retObj).to.equal(10);




    }).timeout(10000)


    it('redis hget hset hgetAll', async () => {

        const simpleRedis = new RedisService('localhost:6379');
        let obj = { ttl: 10 };
        await simpleRedis.hset('test', obj);
        let fieldValue = await simpleRedis.hget('test', 'ttl') as any;
        expect(fieldValue).not.null;
        expect(fieldValue).to.equal('10');

        let retVal = await simpleRedis.hgetAll('test');
        expect(retVal).not.null;
        expect(retVal.ttl).exist;
        expect(retVal.ttl).to.equal('10');




    }).timeout(10000)

    it('redis publish', async () => {

        const simpleRedis = new RedisService('localhost:6379');
        let obj = { ttl: 10 };
        await simpleRedis.publish('test.channel', obj);

    }).timeout(10000)


    it('redis sadd sget sismember', async () => {

        const simpleRedis = new RedisService('localhost:6379');
        let obj = { ttl: 10 };
        await simpleRedis.sadd('iplist', '1.2.3.4');
        await simpleRedis.sadd('iplist', '1.2.3.4');
        let result = await simpleRedis.sismember('iplist', '1.2.3.4')
        expect(result == 1).to.be.true;
        await simpleRedis.sremove('iplist', '1.2.3.4');
        result = await simpleRedis.sismember('iplist', '1.2.3.4')
        expect(result == 1).to.be.false;

    }).timeout(10000)


    it('redis publish/subscribe', async () => {

        const simpleRedis = new RedisService('localhost:6379');
        const simpleRedis2 = new RedisService('localhost:6379');
        let obj = { ttl: 10 };
        let isDataReceived = false;
        await simpleRedis.subscribe('test.channel');
        await simpleRedis.onMessage((channel: string, message: string) => {
            isDataReceived = true;
        })
        await simpleRedis2.publish('test.channel', obj);
        await Util.sleep(2000);
        expect(isDataReceived).to.be.true;

    }).timeout(10000)


    it('redis publish/subscribe on close disabled', async () => {

        const simpleRedis = new RedisService('localhost:6379');
        const simpleRedis2 = new RedisService('localhost:6379');
        let obj = { ttl: 10 };
        let isDataReceived = false;
        await simpleRedis.subscribe('test.channel');
        await simpleRedis.onMessage((channel: string, message: string) => {
            isDataReceived = true;
        })
        await simpleRedis2.publish('test.channel', obj);
        await Util.sleep(2000);
        expect(isDataReceived).to.be.true;

        isDataReceived = false;
        await simpleRedis.disconnect();
        await Util.sleep(2000);
        //message will not be received 
        await simpleRedis2.publish('test.channel', obj);
        await Util.sleep(2000);
        expect(isDataReceived).to.be.false;


    }).timeout(10000)


    it('redis scan', async () => {

        const simpleRedis = new RedisService('localhost:6379');

        let obj = { ttl: 10 };
        let isDataReceived = false;
        const channel = Util.randomNumberString();
        await simpleRedis.set('/test/deneme', 'obs');
        await simpleRedis.set('/test/deneme2', 'obs');
        let pos = '';
        const [cursor, results] = await simpleRedis.scan('/test/*', pos);
        expect(cursor).exist;
        expect(cursor).to.equal('0');
        expect(results.length).to.equal(2);


    }).timeout(10000)

    it('redis xadd/xread', async () => {

        const simpleRedis = new RedisService('localhost:6379');

        let obj = { ttl: 10 };
        let isDataReceived = false;
        const channel = Util.randomNumberString();
        await simpleRedis.xadd(channel, { id: 2 }, '1-1');
        const result = await simpleRedis.xread(channel, 1, '', 100);
        expect(result.length).to.equal(1);
        expect(result[0].xreadPos).to.equal('1-1');
        expect(result[0].id).to.equal('2');



    }).timeout(10000)

    it('redis xadd/xreadmulti', async () => {

        const simpleRedis = new RedisService('localhost:6379');

        let obj = { ttl: 10 };
        let isDataReceived = false;
        const channel1 = Util.randomNumberString();
        const channel2 = Util.randomNumberString();
        await simpleRedis.xadd(channel1, { id: 2 }, '1-1');
        await simpleRedis.xadd(channel2, { id: 3 }, '1-3');
        const result = await simpleRedis.xreadmulti([{ pos: '0', key: channel1 }, { pos: '0', key: channel2 }], 2, 100);
        expect(result.length).to.equal(2);
        expect(result[0].channel).to.equal(channel1);
        expect(result[1].channel).to.equal(channel2);
        expect(result[0].items.length).to.equal(1);
        expect(result[0].items[0].xreadPos).to.equal('1-1');
        expect(result[0].items[0].id).to.equal('2');



    }).timeout(10000)



    it('redis xadd/xread', async () => {

        const simpleRedis = new RedisService('localhost:6379');

        let obj = { ttl: 10 };
        let isDataReceived = false;
        const channel = Util.randomNumberString();
        await simpleRedis.xadd(channel, { id: 2 }, '1-1');
        const result = await simpleRedis.xinfo(channel);
        expect(result).exist;
        expect(result['last-generated-id']).exist;



    }).timeout(10000)


    it('test pipeline', async () => {
        const simpleRedis = new RedisService('localhost:6379');

        let pipe = await simpleRedis.multi()
        for (let i = 0; i < 100; ++i) {
            await pipe.hset(`deneme${i}`, { id: i, name: `test${i}` });
        }
        let results = await pipe.exec();

        pipe = await simpleRedis.multi()
        for (let i = 0; i < 105; ++i) {
            await pipe.hgetAll(`deneme${i}`);
        }
        results = await pipe.exec();

        expect(results).exist;


        pipe = await simpleRedis.multi()
        for (let i = 0; i < 100; ++i) {
            await pipe.set(`deneme${i}`, { id: i, name: `test${i}` });
        }
        results = await pipe.exec();

        pipe = await simpleRedis.multi()
        for (let i = 0; i < 105; ++i) {
            await pipe.get(`deneme${i}`);
        }
        results = await pipe.exec();

        expect(results).exist;



    }).timeout(10000);

    it('redis info', async () => {

        const simpleRedis = new RedisService('localhost:6379', undefined, 'single',);
        const info = await simpleRedis.info();
        expect(info.includes(`role:master`)).to.be.true;

    }).timeout(20000);

    it('redis xtrim', async () => {

        const simpleRedis = new RedisService('localhost:6379');
        let key = '/test/stream';
        await simpleRedis.xadd(key, 'test', `${new Date().getTime()}-1`)
        await simpleRedis.xadd(key, 'test', `${new Date().getTime()}-2`)
        await simpleRedis.xadd(key, 'test', `${new Date().getTime()}-3`)
        await simpleRedis.xadd(key, 'test', `${new Date().getTime()}-4`)
        await simpleRedis.xadd(key, 'test', `${new Date().getTime()}-5`)
        await simpleRedis.xtrim(key, `${new Date().getTime() + 10}`);
        const result = await simpleRedis.xread(key, 10, '0', 1000);
        expect(result.length).to.be.equal(0);


    }).timeout(20000);



    it('redis onClose manuel stop', async () => {
        let called = false;
        let calledCount = 0;
        const onClose = async () => {
            called = true;
            calledCount++;
        }
        const simpleRedis = new RedisServiceManuel('localhost:6700', undefined, 'single', onClose);
        try {

            await simpleRedis.set('abc', 'defs');
            await Util.sleep(1000);


        } catch (err) {
            console.log(err);
            try {
                await simpleRedis.disconnect();
            } catch (err) {
                console.log(err);
            }
        }
        expect(called).to.be.true;
        expect(calledCount).to.equal(1);

    }).timeout(20000)

    it('redis onClose manuel stop', async () => {
        let called = false;
        let calledCount = 0;
        const onClose = async () => {
            called = true;
            calledCount++;
        }
        let exception = false;
        const simpleRedis = new RedisServiceManuel('localhost:6379', undefined, 'single', onClose);
        try {

            await simpleRedis.set('abc', 'defs');
            await Util.sleep(1000);
            await simpleRedis.disconnect();

        } catch (err) {
            exception = true;
            console.log(err);
        }
        expect(called).to.be.false;
        expect(calledCount).to.equal(0);
        expect(exception).to.be.false;

    }).timeout(20000);






})

//docker run --net=host --name redis --rm -d redis


import chai from 'chai';
import chaiHttp from 'chai-http';
import { RedisService } from '../src/service/redisService';



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
                console.log(errr);
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
        console.log('finished')



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




})
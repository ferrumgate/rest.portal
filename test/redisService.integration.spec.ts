
//docker run --net=host --name redis --rm -d redis


import chai from 'chai';
import chaiHttp from 'chai-http';
import { RedisService } from '../src/service/redisService';



chai.use(chaiHttp);
const expect = chai.expect;


describe('redisService', () => {


    it('test add remove get', async () => {
        const simpleRedis = new RedisService('localhost:6379,localhost:6390');
        try {


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



        } catch (err) {
            console.log(err);
        }



    }).timeout(10000)

    it('test transaction', async () => {
        const simpleRedis = new RedisService('localhost:6379');
        try {

            let pipe = await simpleRedis.multi()
            await pipe.set('deneme2', 'deneme2', { ttl: '60000' });
            await pipe.get('deneme2')
            let results = await pipe.exec();
            let as = await simpleRedis.get('deneme2', false)

            expect(as).to.equal('deneme2');

        } catch (err) {
            console.log(err);
        }



    }).timeout(10000)

    it('test transaction that will be null and set other', async () => {
        const simpleRedis = new RedisService('localhost:6379');
        try {

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

        } catch (err) {
            console.log(err);
        }



    }).timeout(10000)


    it('test transaction that will terminate transaction', async () => {
        const simpleRedis = new RedisService('localhost:6379');
        try {
            for (let i = 0; i < 1000; ++i) {
                let pipe = await simpleRedis.multi()
                await pipe.set('deneme30', 'deneme30', { ttl: '60000' });
                await pipe.get('deneme30')
                //let results=await pipe.exec();
                let as = await simpleRedis.get('deneme30', false)

                expect(as).to.be.null
            }
            console.log('finished')


        } catch (err) {
            console.log(err);
        }



    }).timeout(10000)


    it('redis set object', async () => {
        try {
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
        } catch (err) {
            console.log(err);
        }




    }).timeout(10000)

    it('redis set number', async () => {
        try {
            const simpleRedis = new RedisService('localhost:6379');
            let obj = { ttl: 10 };
            await simpleRedis.set('test', 10);
            let retObj = await simpleRedis.get('test') as any;
            expect(retObj).not.null;
            expect(retObj).to.equal(10);


        } catch (err) {
            console.log(err);
        }




    }).timeout(10000)




})

//docker run --net=host --name redis --rm -d redis


import chai from 'chai';
import chaiHttp from 'chai-http';
import { Util } from '../src/util';

import { SystemWatcherService } from '../src/service/system/systemWatcherService';
import { Tunnel } from '../src/model/tunnel';
import { RedisServiceManuel } from '../src/service/redisService';




chai.use(chaiHttp);
const expect = chai.expect;


describe('systemWatcherService', () => {
    beforeEach(async () => {
        try {
            const simpleRedis = new RedisServiceManuel('localhost:6379');
            await simpleRedis.flushAll();

        } catch (err) {

        }
    })



    it('startFilling', async () => {

        const simpleRedis = new RedisServiceManuel('localhost:6379', undefined, 'single');
        var hrstart = process.hrtime();
        let total = 0;

        for (let i = 0; i < 2; ++i) {
            const pipeline = await simpleRedis.multi();
            let counter = 0;
            while (counter < 10000) {
                const tunnel = createTunnel();
                await pipeline.hset(`/tunnel/id/${tunnel.id}`, tunnel);
                counter++;
                total++;
            }
            await pipeline.exec();
        }
        let hrend = process.hrtime(hrstart)
        console.info('insert time records:%d (hr): %ds %dms', total, hrend[0], hrend[1] / 1000000);

        const watcher = new SystemWatcherService();
        (watcher as any).gatewayId = '1234';
        watcher.createConnections();
        hrstart = process.hrtime();
        await watcher.startFirstFilling();
        hrend = process.hrtime(hrstart)
        console.info('fill time records:%d (hr): %ds %dms', total, hrend[0], hrend[1] / 1000000);

        expect(watcher.tunnels.size).to.equal(total);


    }).timeout(200000)

    it('startFilling invalid tunnels', async () => {

        const simpleRedis = new RedisServiceManuel('localhost:6379', undefined, 'single');
        var hrstart = process.hrtime();
        let total = 0;

        for (let i = 0; i < 2; ++i) {
            const pipeline = await simpleRedis.multi();
            let counter = 0;
            while (counter < 10000) {
                const tunnel = createTunnel();
                if (counter % 2)
                    delete tunnel.authenticatedTime;
                await pipeline.hset(`/tunnel/id/${tunnel.id}`, tunnel);
                counter++;
                total++;
            }
            await pipeline.exec();
        }
        let hrend = process.hrtime(hrstart)
        console.info('insert time records:%d (hr): %ds %dms', total, hrend[0], hrend[1] / 1000000);

        let updatedTunnelCount = 0;
        const watcher = new SystemWatcherService();
        (watcher as any).gatewayId = '1234';//for test manipulate
        watcher.on('tunnelUpdated', (tun: Tunnel) => {
            updatedTunnelCount++;
        })
        watcher.createConnections();
        hrstart = process.hrtime();
        await watcher.startFirstFilling();
        hrend = process.hrtime(hrstart)
        console.info('fill time records:%d (hr): %ds %dms', total, hrend[0], hrend[1] / 1000000);

        expect(watcher.tunnels.size).to.equal(total / 2);
        expect(updatedTunnelCount).to.equal(total / 2);



    }).timeout(200000)

    function createTunnel(): Tunnel {
        return {
            id: Util.randomNumberString(64), userId: Util.randomNumberString(), authenticatedTime: new Date().toString(),
            assignedClientIp: '10.0.0.3', trackId: Math.floor(Math.random() * 4000000000),
            clientIp: '192.168.1.100', tun: 'tun0', gatewayId: '1234', serviceNetwork: '192.168.0.0/24'
        }
    }

    it('startAgain', async () => {

        const watcher = new SystemWatcherService();
        (watcher as any).gatewayId = '1234';
        let updatedTunnelCount = 0;
        const simpleRedis = new RedisServiceManuel('localhost:6379', undefined, 'single');
        let firstlist = [];
        let total = 0;
        //add 100 items first
        for (let i = 0; i < 1; ++i) {
            const pipeline = await simpleRedis.multi();
            let counter = 0;
            while (counter < 100) {
                const tunnel = createTunnel();
                firstlist.push(tunnel);
                await pipeline.hset(`/tunnel/id/${tunnel.id}`, tunnel);
                counter++;
                total++;
            }
            await pipeline.exec();
        }
        watcher.on('tunnelUpdated', (tun: Tunnel) => {
            updatedTunnelCount++;
        })
        let deletedTunnelcount = 0;
        watcher.on('tunnelDeleted', (tun: Tunnel) => {
            deletedTunnelcount++;
        })
        //start 
        await watcher.startAgain();
        await Util.sleep(3000);
        expect(watcher.tunnels.size).to.equal(100);
        expect(updatedTunnelCount).to.equal(100);
        // add new items
        for (let i = 0; i < 1; ++i) {
            const pipeline = await simpleRedis.multi();
            let counter = 0;
            while (counter < 100) {
                const tunnel = createTunnel();
                await pipeline.hset(`/tunnel/id/${tunnel.id}`, tunnel);
                counter++;
                total++;
            }
            await pipeline.exec();
        }
        await Util.sleep(10000);
        expect(watcher.tunnels.size).to.equal(200);
        expect(deletedTunnelcount).to.equal(0);
        let index = 0;
        //delete half of them , and expire half of them
        for (const item of firstlist) {
            index++;
            if (index % 2)
                await simpleRedis.expire(`/tunnel/id/${item.id}`, 1000);
            else
                await simpleRedis.delete(`/tunnel/id/${item.id}`);
        }
        await Util.sleep(10000);
        expect(watcher.tunnels.size).to.equal(100);
        expect(deletedTunnelcount).to.equal(100);


    }).timeout(200000)


    it('startAgain', async () => {
        const watcher = new SystemWatcherService();
        watcher.onMessage('', '/eleme,/test');
        expect(watcher.waitList.size).to.equal(2);
    })

    it('reset', async () => {
        const watcher = new SystemWatcherService();
        (watcher as any).gatewayId = '1234';
        const simpleRedis = new RedisServiceManuel('localhost:6379', undefined, 'single');
        let firstlist = [];
        let total = 0;
        //add 100 items first
        for (let i = 0; i < 1; ++i) {

            const pipeline = await simpleRedis.multi();
            let counter = 0;
            while (counter < 100) {
                const tunnel = createTunnel();
                firstlist.push(tunnel);
                await pipeline.hset(`/tunnel/id/${tunnel.id}`, tunnel);
                counter++;
                total++;
            }
            await pipeline.exec();

        }
        await watcher.startAgain();

        await Util.sleep(10000);
        expect(watcher.tunnels.size).to.equal(100);
        await watcher.reset();
        expect(watcher.tunnels.size).to.equal(0);




    }).timeout(1000000);

    it('executeWaitlist', async () => {
        const watcher = new SystemWatcherService();
        (watcher as any).gatewayId = '1234';
        await watcher.createConnections();
        const simpleRedis = new RedisServiceManuel('localhost:6379', undefined, 'single');
        let firstlist = [];
        let total = 0;
        //add 100 items first
        for (let i = 0; i < 1; ++i) {

            const pipeline = await simpleRedis.multi();
            let counter = 0;
            while (counter < 100) {
                const tunnel = createTunnel();
                firstlist.push(tunnel);
                await pipeline.hset(`/tunnel/id/${tunnel.id}`, tunnel);
                counter++;
                total++;
            }
            await pipeline.exec();

        }
        firstlist.forEach(x => watcher.waitList.add(`/tunnel/id/${x.id}`));

        let updatedTunnelCount = 0;
        watcher.on('tunnelUpdated', (tun: Tunnel) => {
            updatedTunnelCount++;
        })
        let deletedTunnelcount = 0;
        watcher.on('tunnelDeleted', (tun: Tunnel) => {
            deletedTunnelcount++;
        })

        await watcher.executeWaitList();
        expect(watcher.tunnels.size).to.equal(100);
        expect(updatedTunnelCount).to.equal(100);
        expect(deletedTunnelcount).to.equal(0);
        expect(watcher.waitList.size).to.equal(0);
        ////
        //delete half of it from redis
        for (let x of firstlist.slice(0, 50)) {
            await simpleRedis.delete(`/tunnel/id/${x.id}`);
        }
        //send back again
        firstlist.forEach(x => watcher.waitList.add(`/tunnel/id/${x.id}`));

        await watcher.executeWaitList();
        expect(watcher.tunnels.size).to.equal(50);
        expect(updatedTunnelCount).to.equal(150);
        expect(deletedTunnelcount).to.equal(50);
        expect(watcher.waitList.size).to.equal(0);






    }).timeout(1000000);




})
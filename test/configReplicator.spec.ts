
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { ConfigService } from '../src/service/configService';
import { Util } from '../src/util';
import { RedisService } from '../src/service/redisService';
import { EventService } from '../src/service/eventService';
import { ConfigReplicator } from '../src/service/system/configReplicator';
import { RedisWatcher } from '../src/service/system/redisWatcher';
import { HelperService } from '../src/service/helperService';
import { User } from '../src/model/user';
import { RBACDefault } from '../src/model/rbac';



chai.use(chaiHttp);
const expect = chai.expect;




describe('configReplicator', async () => {

    const redisService = new RedisService();
    before(async () => {

    })
    beforeEach(async () => {
        await redisService.flushAll();
    })
    it('event changed', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('kgWn7f1dtNOjuYdjezf0dR5I3HQIMNrGsUqthIsHHPoeqt',
            filename);
        const redisWatcher = new RedisWatcher();
        await redisWatcher.start();
        const replicator = new ConfigReplicator(configService, redisWatcher, new RedisService(), new RedisService())
        await replicator.start()

        configService.emitEvent({ type: 'saved', path: '/users', data: { id: 'asd' } })
        let isCalled = false;
        configService.events.on('configChanged', () => {
            isCalled = true;
        })
        await Util.sleep(1000);
        const items = await redisService.xread(`/replication/config`, 100, '0', 1000);
        expect(items.length).to.equal(2);
        expect(isCalled).to.be.true;

        await redisWatcher.stop();


    }).timeout(5000);

    it('replicationWrite', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('kgWn7f1dtNOjuYdjezf0dR5I3HQIMNrGsUqthIsHHPoeqt',
            filename);
        const redisWatcher = new RedisWatcher();
        await redisWatcher.start();
        const replicator = new ConfigReplicator(configService, redisWatcher, new RedisService(), new RedisService())
        await replicator.start()

        await replicator.replicationWrite();
        await Util.sleep(1000);
        const items = await redisService.xread(`/replication/config`, 100, '0', 1000);
        expect(items.length).to.equal(1);
        await redisWatcher.stop();

    }).timeout(5000);

    it('replicationTrim', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('kgWn7f1dtNOjuYdjezf0dR5I3HQIMNrGsUqthIsHHPoeqt',
            filename);
        const redisWatcher = new RedisWatcher();
        await redisWatcher.start();
        const replicator = new ConfigReplicator(configService, redisWatcher, new RedisService(), new RedisService())
        await replicator.start()

        await replicator.replicationWrite();
        await Util.sleep(1000);
        await replicator.replicationTrim(new Date().getTime().toString());
        await Util.sleep(1000);
        const items = await redisService.xread(`/replication/config`, 100, '0', 1000);
        expect(items.length).to.equal(0);
        await redisWatcher.stop();

    }).timeout(5000);

    /* function createUser(source: string, username: string, name: string, password?: string) {
        const user: User = {
            source: source,
            username: username,
            id: Util.randomNumberString(16),
            name: name,
            isLocked: false,
            isVerified: false,
            groupIds: [],
            password: Util.createRandomHash(64),
            is2FA: false,
            twoFASecret: Util.randomNumberString(128),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: [RBACDefault.roleUser.id]//every user is with Role User
        }

        return user;
    }
 */
    /*   it('timetest', async () => {
          const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
          const configService = new ConfigService('kgWn7f1dtNOjuYdjezf0dR5I3HQIMNrGsUqthIsHHPoeqt',
              filename);
          for (let i = 0; i < 1000; ++i) {
              configService.config.users.push(createUser('local-local', `usertest${i}@test.com`, `usertest${i}`, 'test'));
          }
          var hrstart = process.hrtime();
          await configService.saveConfigToFile();
          console.log(filename);
          let hrend = process.hrtime(hrstart)
          console.info('fill time records:%d (hr): %ds %dms', 1, hrend[0], hrend[1] / 1000000);
  
          var hrstart2 = process.hrtime();
          await configService.loadConfigFromFile();
          console.log(filename);
          let hrend2 = process.hrtime(hrstart2)
          console.info('fill time records:%d (hr): %ds %dms', 1, hrend2[0], hrend2[1] / 1000000);
  
  
  
      }).timeout(150000); */


})



import chai from 'chai';
import chaiHttp from 'chai-http';
import { User } from '../src/model/user';
import { ConfigService } from '../src/service/configService';
import { RedisService } from '../src/service/redisService';
import { SessionService } from '../src/service/sessionService';
import { Util } from '../src/util';

chai.use(chaiHttp);
const expect = chai.expect;

describe('sessionService', () => {

    const simpleRedis = new RedisService('localhost:6379,localhost:6390');

    beforeEach(async () => {

        await simpleRedis.flushAll();

    })
    function createSampleData() {
        const user: User = {
            username: 'hamza@ferrumgate.com',
            groupIds: [],
            id: 'someid',
            name: 'hamza',
            password: Util.bcryptHash('somepass'),
            source: 'local',
            isVerified: true,
            isLocked: false,
            is2FA: true,
            twoFASecret: 'adfa',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            roleIds: []

        }
        return { user }
    }

    it('createSession', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        const sessionService = new SessionService(configService, simpleRedis);
        const { user } = createSampleData();
        const session = await sessionService.createSession(user, true, '1.2.3.4', 'local');
        const session2 = await simpleRedis.hgetAll(`/session/id/${session.id}`);
        session.is2FA = session.is2FA.toString() as any;

        expect(session).deep.equal(session2);

    }).timeout(10000)

    it('getSession', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        const sessionService = new SessionService(configService, simpleRedis);
        const { user } = createSampleData();
        const session = await sessionService.createSession(user, true, '1.2.3.4', 'local');
        const session2 = await sessionService.getSession(session.id);
        delete session2?.isCrawlerIp
        delete session2?.isProxyIp;
        delete session2?.isHostingIp;
        expect(session).deep.equal(session2);

    }).timeout(10000)

    it('setSession', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        const sessionService = new SessionService(configService, simpleRedis);
        const { user } = createSampleData();
        const session = await sessionService.createSession(user, true, '1.2.3.4', 'local');
        await sessionService.setSession(session.id, { test: 1 });
        const session2 = await sessionService.getSession(session.id);

        expect((session2 as any).test).to.equal('1');

    }).timeout(10000)

    it('setExpire', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        const sessionService = new SessionService(configService, simpleRedis);
        const { user } = createSampleData();
        const session = await sessionService.createSession(user, true, '1.2.3.4', 'local');

        const sidkey = `/session/id/${session.id}`;
        const sidtunkey = `/session/tunnel/${session.id}`;
        await sessionService.addTunnel(session.id, '12121');
        await sessionService.setExpire(session.id);

        const result = await simpleRedis.ttl(sidkey);
        expect(result).to.above(4 * 60 * 1000);
        const result2 = await simpleRedis.ttl(sidtunkey);
        expect(result2).to.above(4 * 50 * 1000);

    }).timeout(10000)

    it('deleteSession', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        const sessionService = new SessionService(configService, simpleRedis);
        const { user } = createSampleData();
        const session = await sessionService.createSession(user, true, '1.2.3.4', 'local');
        await sessionService.deleteSession(session.id);

        const sidkey = `/session/id/${session.id}`;
        const sidtunkey = `/session/tunnel/${session.id}`;
        const result = await simpleRedis.get(sidkey);
        expect(result).not.exist;
        const result2 = await simpleRedis.get(sidtunkey);
        expect(result2).not.exist;

    }).timeout(10000)

    it('addTunnel', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        const sessionService = new SessionService(configService, simpleRedis);
        const { user } = createSampleData();
        const session = await sessionService.createSession(user, true, '1.2.3.4', 'local');

        await sessionService.addTunnel(session.id, '123')

        const sidtunkey = `/session/tunnel/${session.id}`;
        const result = await simpleRedis.sismember(sidtunkey, '123');
        expect(result).to.equal(1);

    }).timeout(10000)
    it('removeTunnel', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        const sessionService = new SessionService(configService, simpleRedis);
        const { user } = createSampleData();
        const session = await sessionService.createSession(user, true, '1.2.3.4', 'local');

        await sessionService.addTunnel(session.id, '123')
        await sessionService.removeTunnel(session.id, '123')
        const sidtunkey = `/session/tunnel/${session.id}`;
        const result = await simpleRedis.sismember(sidtunkey, '123');
        expect(result).to.equal(0);

    }).timeout(10000)

    it('getSessionKeys', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        const sessionService = new SessionService(configService, simpleRedis);
        const { user } = createSampleData();
        const session1 = await sessionService.createSession(user, true, '1.2.3.4', 'local');
        const session2 = await sessionService.createSession(user, true, '1.2.3.5', 'local');
        const session3 = await sessionService.createSession(user, true, '1.2.3.6', 'local');

        const keys = await sessionService.getSessionKeys();
        expect(keys.length).to.equal(3);

    }).timeout(10000)

    it('getAllValidSessions', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
        const sessionService = new SessionService(configService, simpleRedis);
        const { user } = createSampleData();
        const session1 = await sessionService.createSession(user, true, '1.2.3.4', 'local');
        const session2 = await sessionService.createSession(user, true, '1.2.3.5', 'local');
        const session3 = await sessionService.createSession(user, true, '1.2.3.6', 'local');

        const keys = await sessionService.getAllValidSessions(() => true);
        expect(keys.length).to.equal(3);

    }).timeout(10000);
})
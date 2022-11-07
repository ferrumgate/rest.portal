
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { InputService } from '../src/service/inputService';
import { RestfullException } from '../src/restfullException';
import { ErrorCodes } from '../src/restfullException';
import { ConfigService } from '../src/service/configService';
import { Email, EmailService } from '../src/service/emailService';
import { RBAC, RBACDefault } from '../src/model/rbac';
import { Util } from '../src/util';
import { AuthenticationRule } from '../src/model/authenticationPolicy';
import { PolicyService } from '../src/service/policyService';
import { TunnelService } from '../src/service/tunnelService';
import { RedisService } from '../src/service/redisService';
import { AuditService } from '../src/service/auditService';
import { Network } from '../src/model/network';
import { Gateway } from '../src/model/network';
import { Service } from '../src/model/service';
import { User } from '../src/model/user';
import { AuthorizationRule } from '../src/model/authorizationPolicy';





chai.use(chaiHttp);
const expect = chai.expect;




describe('policyService ', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    beforeEach((done) => {

        if (fs.existsSync(filename))
            fs.rmSync(filename);
        done();
    })
    it('checkUserIdOrGroupId', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true


        }

        const policyService = new PolicyService(configService, new TunnelService(configService, redisService), new AuditService())
        let result = await policyService.checkUserIdOrGroupId(rule, { id: 'x', groupIds: [] } as any)
        expect(result).to.be.false;

        let result2 = await policyService.checkUserIdOrGroupId(rule, { id: 'somegroupid', groupIds: [] } as any)
        expect(result2).to.be.true;

        let result3 = await policyService.checkUserIdOrGroupId(rule, { id: 'adae', groupIds: ['somegroupid'] } as any)
        expect(result3).to.be.true;



    }).timeout(5000);


    it('check2FA', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {},
            isEnabled: true


        }

        const policyService = new PolicyService(configService, new TunnelService(configService, redisService), new AuditService())
        let result = await policyService.check2FA(rule, false)
        expect(result).to.be.true;

        let result2 = await policyService.check2FA(rule, true)
        expect(result2).to.be.true;

        rule.profile.is2FA = true;
        let result3 = await policyService.check2FA(rule, false)
        expect(result3).to.be.false;

        let result4 = await policyService.check2FA(rule, true)
        expect(result4).to.be.true;



    }).timeout(5000);


    it('checkIps', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'allow',
            networkId: 'networkId',
            userOrgroupIds: ['somegroupid'],
            profile: {

            },
            isEnabled: true


        }

        const policyService = new PolicyService(configService, new TunnelService(configService, redisService), new AuditService())
        let result = await policyService.checkIps(rule, '1.2.3,4')
        expect(result).to.be.true;

        rule.profile.ips = [{ ip: '192.168.0.1' }]
        let result2 = await policyService.checkIps(rule, '192.168.0.1')
        expect(result2).to.be.true;

        rule.profile.ips = [{ ip: '192.168.0.1' }, { ip: '192.168.9.10/32' }, { ip: '192.168.10.0/24' }]
        let result3 = await policyService.checkIps(rule, '192.168.9.10')
        expect(result3).to.be.true;

        let result4 = await policyService.checkIps(rule, '192.168.10.15')
        expect(result4).to.be.true;

        let result5 = await policyService.checkIps(rule, '192.168.9.11')
        expect(result5).to.be.false;



    }).timeout(5000);



    it('authenticate', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isEnabled: true
        }
        const gateway: Gateway = {
            id: '123kasdfa',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }

        configService.config.networks = [net];
        configService.config.gateways = [gateway];

        let redisValue = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', hostId: gateway.id };
        await redisService.hset(`/tunnel/id/testsession`, redisValue);

        const policyService = new PolicyService(configService, new TunnelService(configService, redisService), new AuditService())

        //no tunnel with this key
        try {
            let result = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any, true, 'no tunnel')

        } catch (err) { }
        expect(policyService.authenticateErrorNumber).to.equal(1);


        //no gateway

        try {
            await redisService.hset(`/tunnel/id/testsession`, { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', hostId: 'non absent gateway' });
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any, true, 'testsession')
        } catch (err) { }
        expect(policyService.authenticateErrorNumber).to.equal(2);


        //no network

        try {
            const newGateway = Util.clone<Gateway>(gateway);
            newGateway.networkId = 'not absent';
            configService.config.gateways = [newGateway];
            await redisService.hset(`/tunnel/id/testsession`, { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', hostId: newGateway.id });
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any, true, 'testsession')
        } catch (err) { }
        expect(policyService.authenticateErrorNumber).to.equal(4);

        configService.config.gateways = [gateway];

        //rule drop
        let rule: AuthenticationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            action: 'deny',
            networkId: net.id,
            userOrgroupIds: ['somegroupid'],
            profile: {
                is2FA: true,
                ips: [{ ip: '10.0.0.0/24' }]
            },
            isEnabled: true


        }
        configService.config.authenticationPolicy.rules = [rule];

        try {

            configService.config.gateways = [gateway];
            await redisService.hset(`/tunnel/id/testsession`, { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', hostId: gateway.id });
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any, true, 'testsession')
        } catch (err) { }
        expect(policyService.authenticateErrorNumber).to.equal(10);



        rule.action = 'allow';
        configService.config.authenticationPolicy.rules = [rule];

        try {

            configService.config.gateways = [gateway];
            await redisService.hset(`/tunnel/id/testsession`, { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', hostId: gateway.id });
            let result2 = await policyService.authenticate({ id: 'someid', groupIds: ['somegroupid'] } as any, true, 'testsession')
        } catch (err) { }
        expect(policyService.authenticateErrorNumber).to.equal(0);









    }).timeout(5000);



    it('authorize', async () => {
        const redisService = new RedisService();
        let configService = new ConfigService('AuX165Jjz9VpeOMl3msHbNAncvDYezMg', filename);
        configService.config.authenticationPolicy.rules = [];

        const net: Network = {
            id: '1ksfasdfasf',
            name: 'somenetwork',
            labels: [],
            serviceNetwork: '100.64.0.0/16',
            clientNetwork: '192.168.0.0/24',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            isEnabled: true
        }
        const gateway: Gateway = {
            id: '123kasdfa',
            name: 'aserver',
            labels: [],
            networkId: net.id,
            isEnabled: true,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString()
        }

        const service: Service = {
            id: Util.randomNumberString(),
            name: 'mysql-dev',
            isEnabled: true,
            labels: [],
            host: '1.2.3.4',
            networkId: net.id,
            tcp: 3306, assignedIp: '1.3',
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),

        }
        configService.config.services = [service];
        configService.config.networks = [net];
        configService.config.gateways = [gateway];

        let redisValue = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', trackId: 3, hostId: gateway.id, is2FA: true };
        await redisService.hset(`/tunnel/id/testsession`, redisValue);
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession');
        await redisService.set(`/tunnel/trackId/3`, 'testsession');

        const policyService = new PolicyService(configService, new TunnelService(configService, redisService), new AuditService())

        //no client with this key
        try {
            let result = await policyService.authorize(9, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(1);

        //no tunnel with this key
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession2');
        await redisService.set(`/tunnel/trackId/3`, 'testsession2');
        try {
            let result = await policyService.authorize(3, service.id)

        } catch (err) {
            console.log(err);
        }
        expect(policyService.authorizeErrorNumber).to.equal(3);


        //no user
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession');
        await redisService.set(`/tunnel/trackId/3`, 'testsession');
        try {
            let result = await policyService.authorize(3, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(4);


        const user1: User = {
            username: 'hamza@ferrumgate.com',
            id: 'someid',
            name: 'hamza',
            source: 'local',
            roleIds: ['Admin'],
            isLocked: false, isVerified: true,
            password: Util.bcryptHash('somepass'),
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            groupIds: ['ad']

        }
        configService.config.users = [user1];

        //no service
        let redisValue2 = { id: 'testsession', clientIp: '10.0.0.2', tun: 'tun100', trackId: 3, hostId: gateway.id, is2FA: true, userId: user1.id };
        await redisService.hset(`/tunnel/id/testsession`, redisValue2);
        configService.config.services = [];
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession');
        await redisService.set(`/tunnel/trackId/3`, 'testsession');
        try {
            let result = await policyService.authorize(3, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(5);
        configService.config.services = [service];



        //service disabled
        service.isEnabled = false;
        configService.config.services = [service];
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession');
        await redisService.set(`/tunnel/trackId/3`, 'testsession');
        try {
            let result = await policyService.authorize(3, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(6);
        service.isEnabled = true;

        //no network
        configService.config.networks = [];
        await redisService.set(`/tunnel/ip/10.0.0.2`, 'testsession');
        await redisService.set(`/tunnel/trackId/3`, 'testsession');
        try {
            let result = await policyService.authorize(3, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(7);
        configService.config.networks = [net];


        //rule 
        let rule: AuthorizationRule = {
            id: Util.randomNumberString(),
            name: "zero trust",
            networkId: net.id,
            serviceId: service.id,
            userOrgroupIds: [user1.id],

            profile: {
                is2FA: true, isPAM: false
            },
            isEnabled: false

        }
        configService.config.authorizationPolicy.rules = [rule];

        try {
            let result = await policyService.authorize(3, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(100);

        rule.isEnabled = true;


        try {
            let result = await policyService.authorize(3, service.id)

        } catch (err) { }
        expect(policyService.authorizeErrorNumber).to.equal(0); //success








    }).timeout(5000);




})



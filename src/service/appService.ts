import { Util } from "../util";
import { AuditService } from "./auditService";
import { CaptchaService } from "./captchaService";

import { ConfigService } from "./configService";
import { EmailService } from "./emailService";
import { InputService } from "./inputService";
import { LicenceService } from "./licenceService";
import { OAuth2Service } from "./oauth2Service";
import { PolicyService } from "./policyService";
import { RateLimitService } from "./rateLimitService";
import { RedisService } from "./redisService";
import { TemplateService } from "./templateService";
import { TunnelService } from "./tunnelService";
import { TwoFAService } from "./twofaService";
import { logger } from "../common";
import { GatewayService } from "./gatewayService";
import { ConfigPublicListener } from "./system/configPublicListener";
import { ESService } from "./esService";
import { SessionService } from "./sessionService";
import { ActivityService } from "./activityService";
import { SummaryService } from "./summaryService";
import { RedisWatcherService } from "./redisWatcherService";
import { RedisCachedConfigService, RedisConfigService } from "./redisConfigService";
import { SystemLog, SystemLogService } from "./systemLogService";
import { DhcpService } from "./dhcpService";
import { RedisConfigWatchCachedService } from "./redisConfigWatchCachedService";
import { ConfigWatch } from "../model/config";
import { IpIntelligenceService } from "./ipIntelligenceService";
import { ScheduledTasksService } from "./system/sheduledTasksService";
import { ExpressApp } from "../index";
import { exec } from "child_process";
import { PKIService } from "./pkiService";
import { DeviceService } from "./deviceService";
import { LetsEncryptService } from "./letsEncryptService";
import { WatchItem } from "./watchService";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');


/**
 * @summary this is a reference class container for expressjs
 */
export class AppService {
    public rateLimit: RateLimitService;
    public redisService: RedisService;
    public redisLocalService: RedisService;
    public configService: ConfigService;
    public inputService: InputService;
    public captchaService: CaptchaService;
    public licenceService: LicenceService;
    public templateService: TemplateService;
    public emailService: EmailService;
    public twoFAService: TwoFAService;
    public oauth2Service: OAuth2Service;
    public tunnelService: TunnelService;
    public policyService: PolicyService;
    public auditService: AuditService;
    public gatewayService: GatewayService;
    public esService: ESService;
    public sessionService: SessionService;
    public activityService: ActivityService;
    public summaryService: SummaryService;
    public systemLogService: SystemLogService;
    public dhcpService: DhcpService;
    public ipIntelligenceService: IpIntelligenceService;
    public pkiService: PKIService;
    public deviceService: DeviceService;
    public letsEncryptService: LetsEncryptService;

    /**
     *
     */
    constructor(
        cfg?: ConfigService, rateLimit?: RateLimitService,
        redis?: RedisService, redisLocal?: RedisService, input?: InputService,
        captcha?: CaptchaService, licence?: LicenceService,
        template?: TemplateService, email?: EmailService,
        twoFA?: TwoFAService, oauth2?: OAuth2Service,
        tunnel?: TunnelService, audit?: AuditService,
        es?: ESService,
        policy?: PolicyService,
        gateway?: GatewayService,
        session?: SessionService,
        activity?: ActivityService,
        summary?: SummaryService,
        dhcp?: DhcpService,
        systemLog?: SystemLogService,
        ipIntelligenceService?: IpIntelligenceService,
        pkiService?: PKIService,
        deviceService?: DeviceService,
        letsEncryptService?: LetsEncryptService,

    ) {
        //create self signed certificates for JWT
        this.systemLogService = systemLog || new SystemLogService(AppService.createRedisService(), AppService.createRedisService(), process.env.ENCRYPT_KEY || Util.randomNumberString(32), `rest.portal/${(process.env.GATEWAY_ID || Util.randomNumberString(16))}`)
        this.configService = cfg ||
            process.env.CONFIGSERVICE_TYPE === 'CONFIG' ?
            new ConfigService(process.env.ENCRYPT_KEY || Util.randomNumberString(32), `/tmp/${Util.randomNumberString(16)}_config.yaml`) :
            new RedisCachedConfigService(AppService.createRedisService(), AppService.createRedisService(), this.systemLogService,
                process.env.ENCRYPT_KEY || Util.randomNumberString(32), `rest.portal/${(process.env.GATEWAY_ID || Util.randomNumberString(16))}`,
                '/etc/ferrumgate/config.yaml', 15000);
        this.redisService = redis || AppService.createRedisService()
        this.redisLocalService = redisLocal || AppService.createRedisLocalService()
        this.rateLimit = rateLimit || new RateLimitService(this.configService, this.redisService);
        this.inputService = input || new InputService();
        this.captchaService = captcha || new CaptchaService(this.configService);
        this.licenceService = licence || new LicenceService(this.configService);
        this.templateService = template || new TemplateService(this.configService);
        this.emailService = email || new EmailService(this.configService);
        this.twoFAService = twoFA || new TwoFAService();
        this.sessionService = session || new SessionService(this.configService, this.redisService);
        this.oauth2Service = oauth2 || new OAuth2Service(this.configService, this.sessionService);
        this.dhcpService = dhcp || new DhcpService(this.configService, this.redisService);
        this.tunnelService = tunnel || new TunnelService(this.configService, this.redisService, this.dhcpService);
        this.esService = es || new ESService(this.configService);
        this.activityService = activity || new ActivityService(this.redisLocalService, this.esService);
        this.auditService = audit || new AuditService(this.configService, this.redisLocalService, this.esService);
        this.ipIntelligenceService = ipIntelligenceService || new IpIntelligenceService(this.configService, this.redisService, this.inputService, this.esService);
        this.policyService = policy || new PolicyService(this.configService, this.ipIntelligenceService);
        this.gatewayService = gateway || new GatewayService(this.configService, this.redisService);
        this.summaryService = summary || new SummaryService(this.configService, this.tunnelService, this.sessionService, this.redisService, this.esService);
        this.pkiService = pkiService || new PKIService(this.configService);
        this.deviceService = deviceService || new DeviceService(this.configService, this.redisLocalService, this.esService);
        this.letsEncryptService = letsEncryptService || new LetsEncryptService(this.configService, this.redisService, this.systemLogService, process.env.ACME_CHALLENGE || '/tmp/acme-challenge')


        this.configureES = new EventBufferedExecutor(async () => {
            await this.reconfigureES();
        })
        this.configureHttps = new EventBufferedExecutor(async () => {
            await this.reconfigureHttps();
        })
        this.configurePKI = new EventBufferedExecutor(async () => {
            await this.reconfigurePKI();
        })

        this.configureLetsEncrypt = new EventBufferedExecutor(async () => {
            await this.reconfigureLetsEncrypt();
        })

    }

    static createRedisService() {
        return new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS);
    }
    static createRedisLocalService() {
        return new RedisService(process.env.REDIS_LOCAL_HOST || "localhost:6379", process.env.REDIS_LOCAL_PASS);
    }
    configureES: EventBufferedExecutor;
    public async reconfigureES() {

        const es = await this.configService.getES();
        if (es.host)
            await this.esService.reConfigure(es.host, es.user, es.pass);
        else
            await this.esService.reConfigure(process.env.ES_HOST || 'https://localhost:9200', process.env.ES_USER, process.env.ES_PASS);
    }

    configureHttps: EventBufferedExecutor;
    public async reconfigureHttps() {
        await ExpressApp.https.start();

    }
    configurePKI: EventBufferedExecutor;
    public async reconfigurePKI() {
        //TODO

    }

    configureLetsEncrypt: EventBufferedExecutor;
    public async reconfigureLetsEncrypt() {
        await this.letsEncryptService.reconfigure();

    }

    async start() {


        await this.configService.start();
        await this.systemLogService.start(true);
        //prepare es
        this.configService.events.on('ready', async () => {
            await this.configureES.push('ready');
            await this.configureHttps.push('ready');
            await this.configurePKI.push('ready');

        })
        this.configService.events.on('configChanged', async (data: ConfigWatch<any>) => {
            if (data.path == '/config/es')
                await this.configureES.push(data.path);
            if (data.path == '/config/ipIntelligence/sources')
                await this.ipIntelligenceService.reConfigure();//no need to start configure
            if (data.path == '/config/webSSLCertificate') {
                await this.configureHttps.push(data.path);
                await this.configureLetsEncrypt.push(data.path);
            }
            if (data.path == '/config/caSSLCertificate')
                await this.configurePKI.push(data.path);
            if (data.path == '/config/inSSLCertificates')
                await this.configurePKI.push(data.path);
            if (data.path == '/config/url') {
                await this.configureLetsEncrypt.push(data.path);
            }

        });
        //lets encrypt service
        this.configService.events.on('data', async (data: WatchItem<ConfigWatch<any>>) => {
            if (data.val.path.startsWith('/system/letsencrypt'))
                await this.letsEncryptService.execute(data.val);
        });
        await this.configureES.push('');



    }
    async stop() {
        await this.configureES.stop();
        await this.configureHttps.stop();
        await this.configurePKI.stop();
        await this.configService.stop();
        await this.systemLogService.stop(true);
        await this.activityService.stop();
        await this.auditService.stop();
    }


}
/**
 * @summary a system service that starts other services
 * @remarks we dont need any more this class
 */

export class AppSystemService {

    //public redisSlaveWatcher: RedisWatcherService;
    public scheduledTasks: ScheduledTasksService;
    // public configPublicListener: ConfigPublicListener;



    /**
     *
     */
    constructor(app: AppService, scheduledTasks?: ScheduledTasksService
    ) {
        //this.redisSlaveWatcher = redisSlaveWatcher || new RedisWatcherService(process.env.REDIS_SLAVE_HOST || 'localhost:6379', process.env.REDIS_SLAVE_PASS);
        this.scheduledTasks = scheduledTasks || new ScheduledTasksService();
        //  this.configPublicListener = configPublic || new ConfigPublicListener(app.configService, this.createRedisSlave(), this.redisSlaveWatcher);


    }
    /*  createRedisSlave() {
         return new RedisService(process.env.REDIS_SLAVE_HOST || 'localhost:6379', process.env.REDIS_SLAVE_PASS)
     } */
    async start() {
        //await this.redisSlaveWatcher.start();
        await this.scheduledTasks.start();


        //await this.configPublicListener.start();
        //await this.auditLogToES.start();
        //await this.activityLogToES.start();
    }
    async stop() {
        //await this.redisSlaveWatcher.stop();
        await this.scheduledTasks.stop();

        //await this.configPublicListener.stop();
        //await this.auditLogToES.stop();
        //await this.activityLogToES.stop();
    }
}

export class EventBufferedExecutor {

    eventList: string[] = [];
    execute: any;
    errorOccured = false;
    interval: any = null;
    work = true;
    constructor(executor: () => Promise<void>) {
        this.execute = async () => {
            await executor();
        }
    }
    public async push(path: string) {
        this.eventList.push(path);
        if (this.interval)
            return;
        this.interval = setIntervalAsync(async () => {
            while (this.eventList.length && this.work) {
                try {
                    let lenght = this.eventList.length;
                    await this.execute();
                    this.eventList.splice(0, lenght);
                    this.errorOccured = false;
                } catch (err) {
                    logger.error(err);
                    this.errorOccured = true;
                }
                await Util.sleep(this.errorOccured ? 5000 : 1000);

            }
            clearIntervalAsync(this.interval);

        }, this.errorOccured ? 5000 : 1000);
    }
    public stop() {
        this.work = false;
    }


}
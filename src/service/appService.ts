import { Util } from "../util";
import { AuditService } from "./auditService";
import { CaptchaService } from "./captchaService";
import { PolicyAuthzListener } from "./system/policyAuthzListener";
import { ConfigService } from "./configService";
import { EmailService } from "./emailService";
import { EventService } from "./eventService";
import { InputService } from "./inputService";
import { LicenceService } from "./licenceService";
import { OAuth2Service } from "./oauth2Service";
import { PolicyService } from "./policyService";
import { RateLimitService } from "./rateLimitService";
import { RedisService } from "./redisService";
import { TemplateService } from "./templateService";
import { TunnelService } from "./tunnelService";
import { TwoFAService } from "./twofaService";
import { SystemWatcherService } from "./system/systemWatcherService";
import { logger } from "../common";
import { GatewayService } from "./gatewayService";
import { ConfigPublicListener } from "./system/configPublicListener";
import { ESService } from "./esService";
import { AuditLogToES } from "./system/auditLogToES";
import { SessionService } from "./sessionService";
import { ActivityService } from "./activityService";
import { ActivityLogToES } from "./system/activityLogToES";
import { SummaryService } from "./summaryService";
import { RedisWatcher } from "./system/redisWatcher";
import { RedisCachedConfigService, RedisConfigService } from "./redisConfigService";



/**
 * this is a reference class container for expressjs
 */
export class AppService {
    public rateLimit: RateLimitService;
    public redisService: RedisService;
    public configService: ConfigService;
    public inputService: InputService;
    public captchaService: CaptchaService;
    public licenceService: LicenceService;
    public templateService: TemplateService;
    public emailService: EmailService;
    public twoFAService: TwoFAService;
    public oauth2Service: OAuth2Service;
    public tunnelService: TunnelService;
    public eventService: EventService;
    public policyService: PolicyService;
    public auditService: AuditService;
    public gatewayService: GatewayService;
    public esService: ESService;
    public sessionService: SessionService;
    public activityService: ActivityService;
    public summaryService: SummaryService;
    /**
     *
     */
    constructor(
        cfg?: ConfigService, rateLimit?: RateLimitService,
        redis?: RedisService, input?: InputService,
        captcha?: CaptchaService, licence?: LicenceService,
        template?: TemplateService, email?: EmailService,
        twoFA?: TwoFAService, oauth2?: OAuth2Service,
        tunnel?: TunnelService, audit?: AuditService,
        event?: EventService,
        es?: ESService,
        policy?: PolicyService,
        gateway?: GatewayService,
        session?: SessionService,
        activity?: ActivityService,
        summary?: SummaryService
    ) {
        //create self signed certificates for JWT

        this.configService = cfg ||
            process.env.CONFIGSERVICE_TYPE === 'CONFIG' ?
            new ConfigService(process.env.ENCRYPT_KEY || Util.randomNumberString(32), `/tmp/${Util.randomNumberString(16)}_config.yaml`) :
            new RedisCachedConfigService(AppService.createRedisService(), AppService.createRedisService(), process.env.ENCRYPT_KEY || Util.randomNumberString(32), `redisConfig/${(process.env.GATEWAY_ID || Util.randomNumberString(16))}`, '/etc/ferrumgate/config.yaml');
        this.redisService = redis || AppService.createRedisService()
        this.rateLimit = rateLimit || new RateLimitService(this.configService, this.redisService);
        this.inputService = input || new InputService();
        this.captchaService = captcha || new CaptchaService(this.configService);
        this.licenceService = licence || new LicenceService(this.configService);
        this.templateService = template || new TemplateService(this.configService);
        this.emailService = email || new EmailService(this.configService);
        this.twoFAService = twoFA || new TwoFAService();
        this.sessionService = session || new SessionService(this.configService, this.redisService);
        this.oauth2Service = oauth2 || new OAuth2Service(this.configService, this.sessionService);
        this.tunnelService = tunnel || new TunnelService(this.configService, this.redisService);
        this.eventService = event || new EventService(this.configService, this.redisService);
        this.esService = es || new ESService(process.env.ES_HOST, process.env.ES_USER, process.env.ES_PASS);
        this.activityService = activity || new ActivityService(this.redisService, this.esService);
        this.auditService = audit || new AuditService(this.configService, this.redisService, this.esService);
        this.policyService = policy || new PolicyService(this.configService, this.tunnelService);
        this.gatewayService = gateway || new GatewayService(this.configService, this.redisService);
        this.summaryService = summary || new SummaryService(this.configService, this.tunnelService, this.sessionService, this.redisService, this.esService);


    }

    static createRedisService() {
        return new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS);
    }

    async start() {
        await this.configService.start();

    }
    async stop() {
        await this.configService.stop();

    }

}

export class AppSystemService {

    public redisSlaveWatcher: RedisWatcher;
    public systemWatcherService: SystemWatcherService;
    public policyAuthzChannel: PolicyAuthzListener;
    public configPublicListener: ConfigPublicListener;
    public auditLogToES: AuditLogToES;
    public activityLogToES: ActivityLogToES;


    /**
     *
     */
    constructor(app: AppService, redisSlaveWatcher?: RedisWatcher, systemWatcher?: SystemWatcherService,
        policyAuthzChannel?: PolicyAuthzListener, configPublic?: ConfigPublicListener,
        auditLogES?: AuditLogToES, activityLogToES?: ActivityLogToES) {
        this.redisSlaveWatcher = redisSlaveWatcher || new RedisWatcher(process.env.REDIS_SLAVE_HOST || 'localhost:6379', process.env.REDIS_SLAVE_PASS);
        this.systemWatcherService = systemWatcher || new SystemWatcherService();
        this.policyAuthzChannel = policyAuthzChannel || new PolicyAuthzListener(app.policyService, this.systemWatcherService, app.configService);
        this.configPublicListener = configPublic || new ConfigPublicListener(app.configService, this.createRedisSlave(), this.redisSlaveWatcher);
        this.auditLogToES = auditLogES || new AuditLogToES(app.configService, this.createRedisSlave(), this.redisSlaveWatcher);
        this.activityLogToES = activityLogToES || new ActivityLogToES(app.configService, this.createRedisSlave(), this.redisSlaveWatcher);

    }
    createRedisSlave() {
        return new RedisService(process.env.REDIS_SLAVE_HOST || 'localhost:6379', process.env.REDIS_SLAVE_PASS)
    }
    async start() {
        await this.redisSlaveWatcher.start();
        await this.systemWatcherService.start();
        await this.policyAuthzChannel.start();
        await this.configPublicListener.start();
        await this.auditLogToES.start();
        await this.activityLogToES.start();
    }
    async stop() {
        await this.redisSlaveWatcher.stop();
        await this.systemWatcherService.stop();
        await this.policyAuthzChannel.stop();
        await this.configPublicListener.stop();
        await this.auditLogToES.stop();
        await this.activityLogToES.stop();
    }
}
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
        policy?: PolicyService,
        systemWatcher?: SystemWatcherService,
        policyAuthzChannel?: PolicyAuthzListener) {
        //create self signed certificates for JWT

        this.configService = cfg || new ConfigService(process.env.ENCRYPT_KEY || Util.randomNumberString(32), process.env.NODE_ENV == 'development' ? `/tmp/${Util.randomNumberString()}_config.yaml` : '/etc/ferrumgate/config.yaml');
        this.redisService = redis || new RedisService(process.env.REDIS_HOST || "localhost:6379", process.env.REDIS_PASS)
        this.rateLimit = rateLimit || new RateLimitService(this.configService, this.redisService);
        this.inputService = input || new InputService();
        this.captchaService = captcha || new CaptchaService(this.configService);
        this.licenceService = licence || new LicenceService(this.configService);
        this.templateService = template || new TemplateService(this.configService);
        this.emailService = email || new EmailService(this.configService);
        this.twoFAService = twoFA || new TwoFAService();
        this.oauth2Service = oauth2 || new OAuth2Service(this.configService);
        this.tunnelService = tunnel || new TunnelService(this.configService, this.redisService);
        this.eventService = event || new EventService(this.configService, this.redisService);
        this.auditService = audit || new AuditService();
        this.policyService = policy || new PolicyService(this.configService, this.tunnelService, this.auditService);


    }

}

export class AppSystemService {

    public systemWatcherService: SystemWatcherService;
    public policyAuthzChannel: PolicyAuthzListener;
    /**
     *
     */
    constructor(app: AppService, systemWatcher?: SystemWatcherService,
        policyAuthzChannel?: PolicyAuthzListener) {
        this.systemWatcherService = systemWatcher || new SystemWatcherService();
        this.policyAuthzChannel = policyAuthzChannel || new PolicyAuthzListener(app.policyService, this.systemWatcherService);

    }
    async start() {
        await this.systemWatcherService.start();
        await this.policyAuthzChannel.start();
    }
    async stop() {
        await this.systemWatcherService.stop();
        await this.policyAuthzChannel.stop();
    }
}
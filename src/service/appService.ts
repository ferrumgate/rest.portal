import { throws } from "assert";
import { Util } from "../util";
import { CaptchaService } from "./captchaService";
import { ConfigService } from "./configService";
import { EmailService } from "./emailService";
import { InputService } from "./inputService";
import { LicenceService } from "./licenceService";
import { OAuth2Service } from "./oauth2Service";
import { RateLimitService } from "./rateLimitService";
import { RedisService } from "./redisService";
import { TemplateService } from "./templateService";
import { TunnelService } from "./tunnelService";
import { TwoFAService } from "./twofaService";

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
    /**
     *
     */
    constructor(
        cfg?: ConfigService, rateLimit?: RateLimitService,
        redis?: RedisService, input?: InputService,
        captcha?: CaptchaService, licence?: LicenceService,
        template?: TemplateService, email?: EmailService,
        twoFA?: TwoFAService, oauth2?: OAuth2Service,
        tunnel?: TunnelService) {
        this.configService = cfg || new ConfigService(process.env.ENCRYPT_KEY || Util.randomNumberString(32), process.env.NODE_ENV == 'development' ? '/tmp/config.yaml' : '/etc/rest.portal/config.yaml');
        this.redisService = redis || new RedisService(process.env.REDIS_HOST || "localhost:6379")
        this.rateLimit = rateLimit || new RateLimitService(this.configService, this.redisService);
        this.inputService = input || new InputService();
        this.captchaService = captcha || new CaptchaService(this.configService);
        this.licenceService = licence || new LicenceService(this.configService);
        this.templateService = template || new TemplateService(this.configService);
        this.emailService = email || new EmailService(this.configService);
        this.twoFAService = twoFA || new TwoFAService();
        this.oauth2Service = oauth2 || new OAuth2Service(this.configService);
        this.tunnelService = tunnel || new TunnelService(this.configService);

    }

}
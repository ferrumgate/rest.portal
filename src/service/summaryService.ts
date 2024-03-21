import { SummaryActive, SummaryConfig } from "../model/summary";
import { ConfigService } from "./configService";
import { ESService, SearchSummaryRequest, SearchSummaryUserRequest } from "./esService";
import { RedisService } from "./redisService";
import { SessionService } from "./sessionService";
import { TunnelService } from "./tunnelService";





/**
 * @summary all summary functions
 */
export class SummaryService {


    constructor(private configService: ConfigService,
        private tunnelService: TunnelService,
        private sessionService: SessionService,
        private redisService: RedisService, private esService: ESService) {


    }


    async getSummaryConfig() {
        const sum: SummaryConfig = {
            userCount: await this.configService.getUserCount(),
            groupCount: await this.configService.getGroupCount(),
            networkCount: await this.configService.getNetworkCount(),
            gatewayCount: await this.configService.getGatewayCount(),
            authnCount: await this.configService.getAuthenticationPolicyRuleCount(),
            authzCount: await this.configService.getAuthorizationPolicyRuleCount(),
            serviceCount: await this.configService.getServiceCount()

        }
        return sum;
    }

    async getSummaryActive() {

        const sum: SummaryActive = {
            sessionCount: (await this.sessionService.getSessionKeys()).length,
            tunnelCount: (await this.tunnelService.getTunnelKeys()).length
        }
        return sum;
    }

    async getSummaryLoginTry(request: SearchSummaryRequest) {
        return await this.esService.getSummaryLoginTry(request);
    }

    async getSummaryCreateTunnel(request: SearchSummaryRequest) {
        return await this.esService.getSummaryCreateTunnel(request);
    }
    async getSummary2faCheck(request: SearchSummaryRequest) {
        return await this.esService.getSummary2faCheck(request);
    }

    async getSummaryUserLoginSuccess(request: SearchSummaryRequest) {
        return await this.esService.getSummaryUserLoginSuccess(request);
    }

    async getSummaryUserLoginFailed(request: SearchSummaryRequest) {
        return await this.esService.getSummaryUserLoginFailed(request);
    }

    async getSummaryUserLoginTry(request: SearchSummaryUserRequest) {
        return await this.esService.getSummaryUserLoginTry(request);
    }

    async getSummaryUserLoginTryHours(request: SearchSummaryUserRequest) {
        return await this.esService.getSummaryUserLoginTryHours(request);
    }







}
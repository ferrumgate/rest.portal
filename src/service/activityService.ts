import { Util } from "../util";
import { AuditLog } from "../model/auditLog";
import { AuthSession } from "../model/authSession";
import { Service } from "../model/service";
import { User } from "../model/user";

import { ConfigService } from "./configService";
import { ESService, SearchActivityLogsRequest } from "./esService";
import { RedisService } from "./redisService";
import { logger } from "../common";
import * as odiff from 'deep-object-diff';
import { Gateway, Network } from "../model/network";
import { EmailSettings } from "../model/emailSettings";
import { Captcha } from "../model/captcha";
import { AuthenticationRule } from "../model/authenticationPolicy";
import { BaseAuth } from "../model/authSettings";
import { AuthorizationRule } from "../model/authorizationPolicy";
import { Group } from "../model/group";
import { off } from "process";
import { stringify } from "querystring";
import { ActivityLog } from "../model/activityLog";

const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

/**
 * @summary all system activities
 */
export class ActivityService {
    /**
     *
     */

    trimInterval: any;

    constructor(private redisService: RedisService, private esService: ESService) {

        this.trimInterval = setIntervalAsync(async () => {
            await this.trimStream();
        }, 1 * 60 * 60 * 1000)
    }


    async save(act: ActivityLog) {
        const base64 = Buffer.from(JSON.stringify(act)).toString('base64')
        await this.redisService.xadd('/logs/activity', { data: base64, type: 'b64' });
    }



    async trimStream(min?: string) {
        try {
            await this.redisService.xtrim('/logs/activity', min || (new Date().getTime() - 1 * 60 * 60 * 1000).toString());

        } catch (err) {
            logger.error(err);
        }
    }
    /**
     * for testing we need this
     */
    async stop() {
        if (this.trimInterval)
            clearIntervalAsync(this.trimInterval);
        this.trimInterval = null;
    }

    async search(req: SearchActivityLogsRequest) {
        return await this.esService.searchActivityLogs(req);
    }




}
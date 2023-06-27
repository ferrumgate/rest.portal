import { Util } from "../util";
import { AuditLog } from "../model/auditLog";
import { AuthSession } from "../model/authSession";
import { Service } from "../model/service";
import { User } from "../model/user";

import { ConfigService } from "./configService";
import { ESService, SearchAuditLogsRequest } from "./esService";
import { RedisService } from "./redisService";
import { logger } from "../common";
import * as odiff from 'deep-object-diff';
import { Gateway, Network } from "../model/network";
import { EmailSetting } from "../model/emailSetting";
import { Captcha } from "../model/captcha";
import { AuthenticationRule } from "../model/authenticationPolicy";
import { AuthCommon, BaseAuth } from "../model/authSettings";
import { AuthorizationRule } from "../model/authorizationPolicy";
import { Group } from "../model/group";
import { ESSetting } from "../model/esSetting";
import { IpIntelligenceList, IpIntelligenceSource } from "../model/ipIntelligence";
import { SSLCertificate } from "../model/cert";
import { DevicePosture } from "../model/authenticationProfile";
import { FqdnIntelligenceSource } from "../model/fqdnIntelligence";
import { FqdnIntelligenceList } from "../model/fqdnIntelligence";
import { BrandSetting } from "../model/brandSetting";
const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

/**
 * @summary config changed events
 */
export class AuditService {

    /**
     *
     */
    public encKey;
    trimInterval: any;
    removePropertyList = ['id', 'password', 'twoFASecret', 'apiKey', 'privateKey', 'publicCrt'];
    constructor(private configService: ConfigService, private redisService: RedisService, private esService: ESService) {
        this.encKey = this.configService.getEncKey();
        this.trimInterval = setIntervalAsync(async () => {
            await this.trimStream();
        }, 1 * 60 * 60 * 1000)

    }
    async trimStream() {
        try {
            await this.redisService.xtrim('/logs/audit', (new Date().getTime() - 1 * 60 * 60 * 1000).toString());

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


    async saveToRedis(auditLog: AuditLog) {

        const strHex = Util.jencrypt(this.encKey, Util.jencode(auditLog)).toString('base64url') //Util.encrypt(this.encKey, JSON.stringify(auditLog), 'base64url')
        await this.redisService.xadd('/logs/audit', { val: strHex });

    }
    async executeTryCatch(func: () => Promise<void>) {
        try {
            await func();
        }
        catch (err) {
            logger.error(err);
        }
    }
    async executeDelete(currentSession: AuthSession, currentUser: User, before?: any, msg?: string, summary?: string) {
        await this.executeTryCatch(async () => {
            if (!before)
                throw new Error("before is null");
            let log: AuditLog = {
                ip: currentSession?.ip || '',
                insertDate: new Date().toISOString(),
                severity: 'warn',
                userId: currentUser.id,
                username: currentUser.username,
                message: msg || '',
                messageSummary: summary || '',
                messageDetail: ObjectDiffer.calculate2(before, {}, this.removePropertyList),
                tags: `${before.id || ''}`
            }
            await this.saveToRedis(log);
        })
    }

    async executeSave(currentSession: AuthSession, currentUser: User, before?: any, after?: any, msg?: string, summary?: string) {
        await this.executeTryCatch(async () => {
            if (!before && !after)
                throw new Error("before and after is null");
            let log: AuditLog = {
                ip: currentSession?.ip || '',
                insertDate: new Date().toISOString(),
                severity: 'warn',
                userId: currentUser.id,
                username: currentUser.username,
                message: msg || '',
                messageSummary: summary || '',
                messageDetail: ObjectDiffer.calculate2(before, after, this.removePropertyList),
                tags: `${before?.id || after?.id}`
            }
            await this.saveToRedis(log);
        })
    }


    async logDeleteService(currentSession: AuthSession, currentUser: User, before?: Service) {

        await this.executeDelete(currentSession, currentUser, before,
            'service deleted',
            `${before?.name || ''}`)

    }
    async logSaveService(currentSession: AuthSession, currentUser: User, before?: Service, after?: Service) {
        await this.executeSave(currentSession, currentUser, before, after,
            `service ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`,)
    }
    async logSaveNetwork(currentSession: AuthSession, currentUser: User, before?: Network, after?: Network) {
        await this.executeSave(currentSession, currentUser, before, after,
            `network ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`,)
    }
    async logDeleteNetwork(currentSession: AuthSession, currentUser: User, before?: Network) {
        await this.executeDelete(currentSession, currentUser, before,
            'network deleted',
            `${before?.name || ''}`)
    }

    async logSetEmailSetting(currentSession: AuthSession, currentUser: User, before?: EmailSetting, after?: EmailSetting) {

        await this.executeSave(currentSession, currentUser, before, after,
            `email settings updated`,
            `${before?.type || after?.type}`,)
    }
    async logSetCaptcha(currentSession: AuthSession, currentUser: User, before?: Captcha, after?: Captcha) {

        await this.executeSave(currentSession, currentUser, before, after,
            `captcha settings updated`,
            ``,)

    }
    async logSetDomain(currentSession: AuthSession, currentUser: User, before?: string, after?: string) {

        await this.executeSave(currentSession, currentUser, before, after,
            `domain settings updated`,
            `${before || after}`)
    }
    async logSetHttpToHttpsRedirect(currentSession: AuthSession, currentUser: User, before?: boolean, after?: boolean) {

        await this.executeSave(currentSession, currentUser, before, after,
            `http to https redirect settings updated`,
            `${before || after}`)
    }
    async logSetUrl(currentSession: AuthSession, currentUser: User, before?: string, after?: string) {
        await this.executeSave(currentSession, currentUser, before, after, 'url updated',
            `${before || after}`)
    }
    async logSaveUser(currentSession: AuthSession, currentUser: User, before?: User, after?: User) {
        await this.executeSave(currentSession, currentUser, before, after,
            `user ${before ? 'updated' : 'created'}`,
            `${before?.username || after?.username}`)

    }
    // take care about writing senstivie data log
    async logSensitiveData(currentSession: AuthSession, currentUser: User, before?: { username: string, [key: string]: any }, after?: { username: string, [key: string]: any }) {

        await this.executeSave(currentSession, currentUser, before, after,
            `user sensitive data ${before ? 'updated' : 'created'}`,
            `${before?.username || after?.username}`)

    }
    async logDeleteUser(currentSession: AuthSession, currentUser: User, before?: User) {
        await this.executeDelete(currentSession, currentUser, before,
            `user deleted`,
            `${before?.username || ''}`);
    }
    async logUpdateAuthenticationRulePos(currentSession: AuthSession, currentUser: User, item: AuthenticationRule, iBefore: number, iAfter: number) {
        await this.executeTryCatch(async () => {
            if (!item)
                throw new Error("before is null");
            let log: AuditLog = {
                ip: currentSession?.ip || '',
                insertDate: new Date().toISOString(),
                severity: 'warn',
                userId: currentUser.id,
                username: currentUser.username,
                message: `authn pos changed`,
                messageSummary: `${iBefore} >>> ${iAfter}`,
                messageDetail: `pos: ${iBefore} >>> ${iAfter}`,
                tags: `${item.id || ''}`
            }
            await this.saveToRedis(log);
        })

    }
    async logDeleteAuthSettingSaml(currentSession: AuthSession, currentUser: User, before?: BaseAuth) {

        await this.executeDelete(currentSession, currentUser, before,
            `auth saml deleted`,
            `${before?.name || ''}`)


    }
    async logAddAuthSettingSaml(currentSession: AuthSession, currentUser: User, before?: BaseAuth, after?: BaseAuth) {
        await this.executeSave(currentSession, currentUser, before, after,
            `auth saml ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`)

    }
    async logDeleteAuthSettingLdap(currentSession: AuthSession, currentUser: User, before?: BaseAuth) {
        await this.executeDelete(currentSession, currentUser, before,
            `auth ldap deleted`,
            `${before?.name || ''}`)

    }
    async logaddAuthSettingLdap(currentSession: AuthSession, currentUser: User, before?: BaseAuth, after?: BaseAuth) {
        await this.executeSave(currentSession, currentUser, before, after,
            `auth ldap ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`)
    }
    async logdeleteAuthSettingOAuth(currentSession: AuthSession, currentUser: User, before?: BaseAuth) {
        await this.executeDelete(currentSession, currentUser, before,
            `auth oauth deleted`,
            `${before?.name || ''}`)
    }
    async logaddAuthSettingOAuth(currentSession: AuthSession, currentUser: User, before?: BaseAuth, after?: BaseAuth) {
        await this.executeSave(currentSession, currentUser, before, after,
            `auth oauth ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`)
    }
    async logsetAuthSettingLocal(currentSession: AuthSession, currentUser: User, before?: BaseAuth, after?: BaseAuth) {
        await this.executeSave(currentSession, currentUser, before, after,
            `auth local ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`)
    }
    async logsetAuthSettingCommon(currentSession: AuthSession, currentUser: User, before?: AuthCommon, after?: AuthCommon) {
        await this.executeSave(currentSession, currentUser, before, after,
            `auth common ${before ? 'updated' : 'created'}`,
            ``)
    }
    async logSaveAuthorizationPolicyRule(currentSession: AuthSession, currentUser: User, before?: AuthorizationRule, after?: AuthorizationRule) {
        await this.executeSave(currentSession, currentUser, before, after,
            `authz rule ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`)
    }
    async logDeleteAuthorizationPolicyRule(currentSession: AuthSession, currentUser: User, before?: AuthorizationRule) {
        await this.executeDelete(currentSession, currentUser, before,
            `authz rule deleted`,
            `${before?.name || after?.name}`)
    }
    async logSaveAuthenticationPolicyRule(currentSession: AuthSession, currentUser: User, before?: AuthenticationRule, after?: AuthenticationRule) {
        await this.executeSave(currentSession, currentUser, before, after,
            `authn rule ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`)
    }
    async logDeleteAuthenticationPolicyRule(currentSession: AuthSession, currentUser: User, before?: AuthenticationRule) {

        await this.executeDelete(currentSession, currentUser, before,
            `authn rule deleted`,
            `${before?.name || after?.name}`)
    }
    async saveAuthorizationPolicyRule(currentSession: AuthSession, currentUser: User, before?: AuthorizationRule, after?: AuthorizationRule) {
        await this.executeSave(currentSession, currentUser, before, after,
            `authn rule ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`)
    }
    async logSaveGateway(currentSession: AuthSession, currentUser: User, before?: Gateway, after?: Gateway) {
        await this.executeSave(currentSession, currentUser, before, after,
            `gateway ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`)
    }
    async logDeleteGateway(currentSession: AuthSession, currentUser: User, before?: Gateway) {
        await this.executeDelete(currentSession, currentUser, before,
            `gateway deleted`,
            `${before?.name || after?.name}`)
    }
    async logDeleteGroup(currentSession: AuthSession, currentUser: User, before?: Group) {
        await this.executeDelete(currentSession, currentUser, before,
            `group deleted`,
            `${before?.name || after?.name}`)
    }
    async logSaveGroup(currentSession: AuthSession, currentUser: User, before?: Group, after?: Group) {
        await this.executeSave(currentSession, currentUser, before, after,
            `group ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`)
    }
    async logSetES(currentSession: AuthSession, currentUser: User, before?: ESSetting, after?: ESSetting) {

        await this.executeSave(currentSession, currentUser, before, after,
            `es settings updated`,
            ``,)
    }
    async logSetBrand(currentSession: AuthSession, currentUser: User, before?: BrandSetting, after?: BrandSetting) {

        await this.executeSave(currentSession, currentUser, before, after,
            `brand settings updated`,
            ``,)
    }
    async logConfigExport(currentSession: AuthSession, currentUser: User) {

        await this.executeSave(currentSession, currentUser, {}, {},
            `config exported`,
            ``,)
    }
    async logConfigImport(currentSession: AuthSession, currentUser: User) {

        await this.executeSave(currentSession, currentUser, {}, {},
            `config imported`,
            ``,)
    }

    async logUserConfirm(currentSession: AuthSession, currentUser: User) {

        await this.executeSave(currentSession, currentUser, {}, {},
            `user confirmed`,
            `${currentUser.username}`)
    }

    async logForgotPassword(currentSession: AuthSession, currentUser: User, username: string) {

        await this.executeSave(currentSession, currentUser, {}, {},
            `password forgotten`,
            `${username}`)
    }

    async logResetPassword(currentSession: AuthSession, currentUser: User) {

        await this.executeSave(currentSession, currentUser, {}, {},
            `password reset`,
            `${currentUser.username}`)
    }

    async logResetPasswordForOtherUser(currentSession: AuthSession, currentUser: User, otherUser: User) {

        await this.executeSave(currentSession, currentUser, {}, { id: otherUser.id, username: otherUser.username },
            `password hard reset`,
            `${otherUser.username}`)
    }



    async search(req: SearchAuditLogsRequest) {
        return await this.esService.searchAuditLogs(req);
    }



    async logSaveIpIntelligenceSource(currentSession: AuthSession, currentUser: User, before?: IpIntelligenceSource, after?: IpIntelligenceSource) {

        await this.executeSave(currentSession, currentUser, before, after,
            `ip intelligence source ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`,)

    }
    async logDeleteIpIntelligenceSource(currentSession: AuthSession, currentUser: User, before?: IpIntelligenceSource, after?: IpIntelligenceSource) {

        await this.executeSave(currentSession, currentUser, before, after,
            `ip intelligence source deleted}`,
            `${before?.name}`,)

    }

    async logSaveIpIntelligenceList(currentSession: AuthSession, currentUser: User, before?: IpIntelligenceList, after?: IpIntelligenceList) {

        await this.executeSave(currentSession, currentUser, before, after,
            `ip intelligence list ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`,)

    }
    async logDeleteIpIntelligenceList(currentSession: AuthSession, currentUser: User, before?: IpIntelligenceList, after?: IpIntelligenceList) {

        await this.executeSave(currentSession, currentUser, before, after,
            `ip intelligence list deleted`,
            `${before?.name}`,)

    }
    async logResetIpIntelligenceList(currentSession: AuthSession, currentUser: User, before?: IpIntelligenceList, after?: IpIntelligenceList) {

        await this.executeSave(currentSession, currentUser, before, before,
            `ip intelligence list reseted`,
            `${before?.name}`,)

    }
    async logDeleteCert(currentSession: AuthSession, currentUser: User, before?: SSLCertificate, after?: SSLCertificate) {

        await this.executeSave(currentSession, currentUser, before, after,
            `certificate deleted`,
            `${before?.name}`,)

    }
    async logSaveCert(currentSession: AuthSession, currentUser: User, before?: SSLCertificate, after?: SSLCertificate) {

        await this.executeSave(currentSession, currentUser, before, after,
            `certificate ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`,)

    }
    async logExportCert(currentSession: AuthSession, currentUser: User, cert: SSLCertificate) {

        await this.executeSave(currentSession, currentUser, {}, {},
            `certificate exported`,
            `${cert?.name}`,)

    }

    async logDeleteDevicePosture(currentSession: AuthSession, currentUser: User, before?: DevicePosture) {
        await this.executeDelete(currentSession, currentUser, before,
            `device posture deleted`,
            `${before?.name || after?.name}`)
    }
    async logSaveDevicePosture(currentSession: AuthSession, currentUser: User, before?: DevicePosture, after?: DevicePosture) {
        await this.executeSave(currentSession, currentUser, before, after,
            `device posture ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`)
    }


    async logSaveFqdnIntelligenceSource(currentSession: AuthSession, currentUser: User, before?: FqdnIntelligenceSource, after?: FqdnIntelligenceSource) {

        await this.executeSave(currentSession, currentUser, before, after,
            `fqdn intelligence source ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`,)

    }
    async logDeleteFqdnIntelligenceSource(currentSession: AuthSession, currentUser: User, before?: FqdnIntelligenceSource, after?: FqdnIntelligenceSource) {

        await this.executeSave(currentSession, currentUser, before, after,
            `fqdn intelligence source deleted}`,
            `${before?.name}`,)

    }

    async logSaveFqdnIntelligenceList(currentSession: AuthSession, currentUser: User, before?: FqdnIntelligenceList, after?: FqdnIntelligenceList) {

        await this.executeSave(currentSession, currentUser, before, after,
            `fqdn intelligence list ${before ? 'updated' : 'created'}`,
            `${before?.name || after?.name}`,)

    }
    async logDeleteFqdnIntelligenceList(currentSession: AuthSession, currentUser: User, before?: FqdnIntelligenceList, after?: FqdnIntelligenceList) {

        await this.executeSave(currentSession, currentUser, before, after,
            `fqdn intelligence list deleted`,
            `${before?.name}`,)

    }
    async logResetFqdnIntelligenceList(currentSession: AuthSession, currentUser: User, before?: IpIntelligenceList, after?: IpIntelligenceList) {

        await this.executeSave(currentSession, currentUser, before, before,
            `fqdn intelligence list reseted`,
            `${before?.name}`,)

    }




}
/**
 * @summary calculates a diff format for auditing
 */
export class ObjectDiffer {
    static calculate(before: any, after: any, removeFields: string[] = [], mapFields: Map<string, string> = new Map()) {
        let obj = odiff.detailedDiff(before, after);
        let msg: Map<string, string> = new Map();
        try {
            function toString(obj: any, start: string): string {
                if (obj == null || obj == undefined) start = start + 'null,';
                else
                    if (typeof (obj) == 'function') start = start + 'null,';
                    else
                        if (typeof (obj) == "symbol") start = start + 'null,';
                        else
                            if (typeof (obj) == 'object') {
                                let added = false;
                                for (const key of Object.keys(obj)) {
                                    if (!removeFields.includes(key)) {
                                        added = true;
                                        start = start + toString(obj[key], `{ .${mapFields.get(key) || key}: `) + ',';
                                    }
                                    if (added) {
                                        start = start.substring(0, start.length - 1) + ' }';
                                    }
                                }
                            } else
                                start = start + obj.toString() + ',';
                if (start && start.endsWith(','))
                    return start.substring(0, start.length - 1);
                return start;
            }
            function mapField(field: string) {
                return '.' + field.split('.').filter(x => x).map(x => mapFields.get(x) || x).join('.');
            }
            function getObjValue(obj: any, field: string | string[]): string {
                if ((obj == null || obj == undefined)) return 'null';
                if (typeof (field) == 'string') {
                    if (field.startsWith('.added'))
                        field = field.substring('.added'.length + 1);
                    if (field.startsWith('.updated'))
                        field = field.substring('.updated'.length + 1);
                    if (field.startsWith('.deleted'))
                        field = field.substring('.deleted'.length + 1);
                }
                const fields = Array.isArray(field) ? field : field.split('.').filter(x => x);
                if (!fields.length) return (obj == null || obj == undefined) ? 'null' : toString(obj, '');
                const value = obj[fields[0]];
                if (value == null || value == undefined) return 'null';
                return getObjValue(value, fields.slice(1));

            }
            function getFieldValue(obj: any, map: Map<string, string>, baseField = '') {
                const mappedField = mapField(baseField);
                for (const sp of baseField.split('.').filter(x => x)) {
                    if (removeFields.includes(sp))
                        return;
                }

                if (typeof (obj) == "undefined" || typeof (obj) == "symbol" || typeof (obj) == "function") {
                    if (!map.has(mappedField)) {
                        const currentValue = getObjValue(before, baseField);
                        map.set(mappedField, currentValue + ' >>> ' + 'null');
                    }
                    else {
                        const currentValue = getObjValue(before, baseField);
                        map.set(mappedField, mappedField + ',' + currentValue + ' >>> ' + 'null');
                    }
                } else
                    if (typeof (obj) == "object") {
                        if (obj == null) {
                            if (!map.has(mappedField)) {
                                const currentValue = getObjValue(before, baseField);
                                map.set(mappedField, currentValue + ' >>> ' + 'null');
                            }
                            else {
                                const currentValue = getObjValue(before, baseField);
                                map.set(mappedField, mappedField + ',' + currentValue + ' >>> ' + 'null');
                            }
                            return;
                        }

                        if (Array.isArray(obj)) {
                            for (let i = 0; i < obj.length; ++i) {
                                getFieldValue(obj[i], map, baseField + '.' + i);// baseField.endsWith('.arr') ? baseField : baseField + '.arr')
                            }
                        } else
                            for (const key of Object.keys(obj)) {
                                getFieldValue(obj[key], map, baseField + '.' + key)
                            }

                    } else {
                        if (!map.has(mappedField)) {
                            const currentValue = getObjValue(before, baseField);
                            map.set(mappedField, currentValue + ' >>> ' + obj);
                        }
                        else {
                            const currentValue = getObjValue(before, baseField);
                            map.set(mappedField, baseField + ', ' + currentValue + ' >>> ' + obj);
                        }
                    }
            }

            getFieldValue(obj, msg, '');

        } catch (err) {
            msg.set('exception', 'err:' + new Date().toISOString());
            logger.error(err);
        }
        return msg;
    }

    static calculate2(before: any, after: any, removeFields: string[] = [], mapFields: Map<string, string> = new Map(), join = ',') {
        const results = ObjectDiffer.calculate(before || {}, after || {}, removeFields, mapFields);
        const msgList: string[] = [];
        results.forEach((value, key) => msgList.push(key + ': ' + value));
        const msgStr = msgList.join(join);
        return msgStr

    }








}
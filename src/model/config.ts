import { AuthenticationPolicy } from "./authenticationPolicy";
import { AuthorizationPolicy } from "./authorizationPolicy";
import { AuthSettings } from "./authSettings";
import { Captcha } from "./captcha";
import { EmailSetting } from "./emailSetting";
import { Group } from "./group";
import { LogoSetting } from "./logoSetting";
import { Gateway, Network } from "./network";
import { RBAC, Right, Role } from "./rbac";
import { Service } from "./service";
import { SSHCertificate } from "./sshCertificate";
import { SSLCertificate } from "./sslCertificate";
import { ESSetting } from "./esSetting";
import { User } from "./user";


type Nullable<T> = T | null | undefined;

// adding new paths here
// also effects redisConfigWatchService
// processExecuteList
export type RPath =
    'lastUpdateTime' |
    'revision' |
    'version' |
    'isConfigured' |
    'domain' |
    'url' |
    'auth/common' |
    'auth/local' |
    'auth/oauth/providers' |
    'auth/ldap/providers' |
    'auth/saml/providers' |
    'jwtSSLCertificate' |
    'sslCertificate' |
    'caSSLCertificate' |
    'users' |
    'groups' |
    'services' |
    'captcha' |
    'email' |
    'logo' |
    'networks' |
    'gateways' |
    'authenticationPolicy/rules' |
    'authenticationPolicy/rulesOrder' |
    'authorizationPolicy/rules' |
    'authorizationPolicy/rulesOrder' |
    'es';



/**
 * @summary when config changed, which field changed, what happened
 */
export interface ConfigWatch<T> {
    path: string, type: 'del' | 'put', val: T, before?: T
}
export interface Config {
    lastUpdateTime: string;
    revision: number;
    version: number;
    /**
     * @summary is default configuration reconfigured
     */
    isConfigured: number;
    /**
     * @summary domain for creating certificates
     * @example ferrumgate.zero
     */
    domain: string;
    /**
     * @summary web page serving adress
     * @example http://local.ferrumgate.com
     */
    url: string;
    auth: AuthSettings,
    jwtSSLCertificate: SSLCertificate,
    sslCertificate: SSLCertificate,
    caSSLCertificate: SSLCertificate,
    //sshCertificate: SSHCertificate,

    users: User[];
    groups: Group[];
    services: Service[];
    captcha: Captcha,
    email: EmailSetting,
    logo: LogoSetting,
    /**
     * @summary RBAC roles and rights
     */
    rbac: RBAC;
    networks: Network[];
    gateways: Gateway[];
    authenticationPolicy: AuthenticationPolicy;
    authorizationPolicy: AuthorizationPolicy;

    // adding new property needs to lookup 
    // redisConfigWatchService 
    // redisConfigWatchCachedService
    es: ESSetting;


}
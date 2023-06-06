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
import { SSLCertificate, SSLCertificateEx } from "./cert";
import { ESSetting } from "./esSetting";
import { User } from "./user";
import { IpIntelligence } from "./ipIntelligence";
import { DevicePosture, DeviceProfile } from "./authenticationProfile";
import { FqdnIntelligence } from "./fqdnIntelligence";


type Nullable<T> = T | null | undefined;

// adding new paths here
// also effects redisConfigWatchService
// processExecuteList
// also redisConfigService getAll, setAll
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
    'webSSLCertificate' |
    'caSSLCertificate' |
    'inSSLCertificates' |
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
    'es' | 'flush' |
    'ipIntelligence/sources' |
    'ipIntelligence/lists' |
    'devicePostures' |
    'fqdnIntelligence/sources' |
    'fqdnIntelligence/lists';




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
    webSSLCertificate: SSLCertificate,
    caSSLCertificate: SSLCertificate,
    /**
     * @summary intermediate certificates
     */
    inSSLCertificates: SSLCertificateEx[],



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


    es: ESSetting;
    //config reset
    flush: number;

    // adding new property needs to lookup 
    // redisConfigWatchService 
    // redisConfigWatchCachedService
    // redisConfigService getConfig and setConfig functions
    ipIntelligence: IpIntelligence;

    //
    devicePostures: DevicePosture[];

    // adding new property needs to lookup 
    // redisConfigWatchService 
    // redisConfigWatchCachedService
    // redisConfigService getConfig and setConfig functions
    fqdnIntelligence: FqdnIntelligence;
}
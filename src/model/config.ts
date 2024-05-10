import { AuthSettings } from "./authSettings";
import { AuthenticationPolicy } from "./authenticationPolicy";
import { DevicePosture } from "./authenticationProfile";
import { AuthorizationPolicy } from "./authorizationPolicy";
import { BrandSetting } from "./brandSetting";
import { Captcha } from "./captcha";
import { SSLCertificate, SSLCertificateEx } from "./cert";
import { Dns } from "./dns";
import { EmailSetting } from "./emailSetting";
import { ESSetting } from "./esSetting";
import { FqdnIntelligence } from "./fqdnIntelligence";
import { Group } from "./group";
import { IpIntelligence } from "./ipIntelligence";
import { LogoSetting } from "./logoSetting";
import { Gateway, Network, Node } from "./network";
import { RBAC } from "./rbac";
import { Service } from "./service";
import { User } from "./user";


type Nullable<T> = T | null | undefined;

// adding new paths here
// also effects redisConfigWatchService
// processExecuteList
// also redisConfigService getConfig, setConfig
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
    'auth/openId/providers' |
    'auth/radius/providers' |
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
    'fqdnIntelligence/lists' |
    'httpToHttpsRedirect' |
    'brand' |
    'dns/records' |
    'nodes';




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
    brand: BrandSetting;
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

    //redirect http requests to https
    httpToHttpsRedirect: boolean;

    //dns
    dns: Dns
    //nodes
    nodes: Node[]
}
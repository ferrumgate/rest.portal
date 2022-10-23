import { AuthenticationPolicy } from "./authenticationPolicy";
import { AuthorizationPolicy } from "./authorizationPolicy";
import { AuthSettings } from "./authSettings";
import { Captcha } from "./captcha";
import { EmailSettings } from "./emailSettings";
import { Group } from "./group";
import { LogoSettings } from "./logoSettings";
import { Gateway, Network } from "./network";
import { RBAC, Right, Role } from "./rbac";
import { Service } from "./service";
import { SSHCertificate } from "./sshCertificate";
import { SSLCertificate } from "./sslCertificate";
import { User } from "./user";

/**
 * @summary when config changed, which field changed, what happened
 */
export interface ConfigEvent {
    type: 'saved' | 'updated' | 'deleted';
    path: string;
    data?: any;
}

export interface ConfigAuditEvent {
    type: 'saved' | 'updated' | 'deleted';
    path: string;
    data?: any;
}

export interface Config {
    /**
     * @summary is default configuration reconfigured
     */
    isConfigured: number;
    /**
     * @summary domain for creating certificates
     * @example ferrumgate.local
     */
    domain: string;
    /**
     * @summary web page serving adress
     * @example http://local.ferrumgate.com
     */
    url: string;
    auth: AuthSettings,
    jwtSSLCertificate: SSLCertificate,
    sshCertificate: SSHCertificate,

    users: User[];
    groups: Group[];
    services: Service[];
    captcha: Captcha,
    email: EmailSettings,
    logo: LogoSettings,
    /**
     * @summary RBAC roles and rights
     */
    rbac: RBAC;
    networks: Network[];
    gateways: Gateway[];
    authenticationPolicy: AuthenticationPolicy;
    authorizationPolicy: AuthorizationPolicy;


}
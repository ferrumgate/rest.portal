import { AuthGoogle, AuthSettings } from "./authSettings";
import { Captcha } from "./captcha";
import { EmailSettings } from "./emailSettings";
import { LogoSettings } from "./logoSettings";
import { Gateway, Network } from "./network";
import { RBAC, Right, Role } from "./rbac";
import { SSHCertificate } from "./sshCertificate";
import { SSLCertificate } from "./sslCertificate";
import { User } from "./user";



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
    captcha: Captcha,
    email: EmailSettings,
    logo: LogoSettings,
    /**
     * @summary RBAC roles and rights
     */
    rbac: RBAC;
    networks: Network[];
    gateways: Gateway[];
}
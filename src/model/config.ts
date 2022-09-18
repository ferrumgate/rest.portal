import { AuthGoogle, AuthOption } from "./authOption";
import { Captcha } from "./captcha";
import { EmailOption } from "./emailOption";
import { LogoOption } from "./logoOption";
import { RBAC, Right, Role } from "./rbac";
import { SSHCertificate } from "./sshCertificate";
import { SSLCertificate } from "./sslCertificate";
import { User } from "./user";



export interface Config {
    /**
     * @summary domain for creating certificates
     * @example ferrumgate.com
     */
    domain: string;
    /**
     * @summary web page serving adress
     * @example http://local.ferrumgate.com
     */
    url: string;
    auth: AuthOption,
    jwtSSLCertificate: SSLCertificate,
    sshCertificate: SSHCertificate,

    users: User[];
    captcha: Captcha,
    email: EmailOption,
    logo: LogoOption,
    /**
     * @summary RBAC roles and rights
     */
    rbac: RBAC;
    /**
     * @summary client sub net like 10.0.0.0/8
     */
    clientNetwork: string;

    /**
     * @summary service ip network
     */
    serviceNetwork: string;
}
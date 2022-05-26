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
     */
    domain: string;
    url: string;
    auth: AuthOption,
    sslCertificate: SSLCertificate,
    sshCertificate: SSHCertificate,

    users: User[];
    captcha: Captcha,
    email: EmailOption,
    logo: LogoOption,
    /**
     * @summary RBAC roles and rights
     */
    rbac: RBAC;
}
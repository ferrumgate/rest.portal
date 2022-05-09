import { AuthGoogle, AuthOption } from "./authOption";
import { Captcha } from "./captcha";
import { EmailOption } from "./emailOption";
import { LogoOption } from "./logoOption";
import { SSHCertificate } from "./sshCertificate";
import { SSLCertificate } from "./sslCertificate";
import { User } from "./user";



export interface Config {
    domain: string;
    url: string;
    auth: AuthOption,
    sslCertificate: SSLCertificate,
    sshCertificate: SSHCertificate,
    users: User[];
    captcha: Captcha,
    email: EmailOption,
    logo: LogoOption,
}
import { EmailOption } from "./emailOption";
import { LogoOption } from "./logoOption";
import { User } from "./user";



export interface Config {
    domain?: string;
    certificates: {
        public?: string,
        private?: string
    },
    sshCertificates: {
        public?: string,
        private?: string,
    },
    users: User[];
    captcha: {
        serverKey?: string;
        clientKey?: string;
    },
    email: EmailOption,
    logo: LogoOption,
}
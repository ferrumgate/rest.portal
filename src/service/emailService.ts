import * as nodemailer from 'nodemailer'
import SMTPPool from 'nodemailer/lib/smtp-pool';
import { logger } from '../common';
import { ErrorCodes, RestfullException } from '../restfullException';



import { ConfigService } from "./configService";

export interface Attachment {
    filename: string;
    content: string;
}
export interface Email {
    to: string;
    cc?: string;
    bcc?: string;
    subject: string;
    text?: string
    html?: string;
    attachments?: Array<Attachment>;

}
class EmailSender {
    transporter: any;
}

class GmailAccount extends EmailSender {

    user: string;
    name: string;
    fromName: string;
    pass: string;
    constructor(name: string, fromName: string, user: string, pass: string) {
        super();

        this.user = user;
        this.pass = pass;
        this.fromName = fromName;

        this.name = name;
        this.transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: user,
                pass: pass
            },
            pool: true
        });
    }
}

class Office365Account extends EmailSender {
    user: string;
    name: string;
    fromName: string;
    pass: string;
    constructor(name: string, fromName: string, user: string, pass: string) {
        super();

        this.user = user;
        this.pass = pass;
        this.fromName = fromName;

        this.name = name;
        this.transporter = nodemailer.createTransport({
            host: 'smtp.office365.com', // Office 365 server
            port: 587,     // secure SMTP
            secure: false, // false for TLS - as a boolean not string - but the default is false so just remove this completely
            auth: {
                user: this.user,
                pass: this.pass
            },
            pool: true,
            requireTLS: true,
            tls: {
                ciphers: 'SSLv3'
            }
        });
    }
}

class SmtpAccount extends EmailSender {

    name: string;


    constructor(name: string, public fromName: string, private host?: string, private port?: string, isSecure?: boolean, public user?: string, private pass?: string) {
        super();

        this.name = name;
        let options: SMTPPool | SMTPPool.Options = {
            host: 'localhost',
            port: 25,     // secure SMTP
            secure: isSecure || false, // false for TLS - as a boolean not string - but the default is false so just remove this completely
            requireTLS: false,
            pool: true,
            tls: {
                ciphers: 'SSLv3',
                rejectUnauthorized: false
            },


        }
        if (this.host)
            options.host = this.host;
        if (this.port)
            options.port = Number(this.port);
        if (this.user && this.pass) {
            options.auth = {
                user: this.user,
                pass: this.pass
            }
        }


        this.transporter = nodemailer.createTransport(options);
    }
}

export class EmailService {
    protected sender: EmailSender | null;
    constructor(private configService: ConfigService) {
        this.sender = null;

    }
    async send(email: Email) {
        const emailOptions = await this.configService.getEmailOptions();
        if (!this.sender) {

            switch (emailOptions.type) {
                case 'google':
                    this.sender = new GmailAccount("gmail", emailOptions.fromname, emailOptions.user, emailOptions.pass);
                    break;
                case 'office365':
                    this.sender = new Office365Account("office", emailOptions.fromname, emailOptions.user, emailOptions.pass);
                    break;
                case 'smtp':
                    this.sender = new SmtpAccount('smtp', emailOptions.fromname, emailOptions.host || 'localhost', emailOptions.port || 25, emailOptions.isSecure || false, emailOptions.user, emailOptions.pass);
                    break;
                default:
                    logger.fatal(`unknown email type`);
                    throw new RestfullException(400, ErrorCodes.ErrBadArgument, "empty configuration");
            }

        }
        let tmp = {
            from: { name: emailOptions.fromName, address: emailOptions.user },
            to: email.to,
            cc: email.cc,
            bcc: email.bcc,
            subject: email.subject,
            text: email.text,
            html: email.html,
            attachments: email.attachments ? email.attachments.map(x => { return { filename: x.filename, content: Buffer.from(x.content, 'base64') } }) : undefined

        }
        await new Promise((resolve, reject) => {
            this.sender?.transporter.sendMail(tmp, function (err: any, info: any) {
                if (err) {
                    logger.error(err.stack);
                    reject(new RestfullException(500, ErrorCodes.ErrInternalError, "email sending failed"))
                } else {
                    logger.info(`email sended to: ${email.to} subject: ${email.subject}`);
                    resolve(info.messageId);
                }
            })

        })
    }
}
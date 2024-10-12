import * as nodemailer from 'nodemailer';
import SMTPPool from 'nodemailer/lib/smtp-pool';
import { logger } from '../common';
import { EmailSetting } from '../model/emailSetting';
import { ErrorCodes, ErrorCodesInternal, RestfullException } from '../restfullException';
let aws = require("@aws-sdk/client-ses");
let { defaultProvider } = require("@aws-sdk/credential-provider-node");

import { ConfigService } from "./configService";
import Axios, { AxiosRequestConfig } from "axios";
import { Util } from '../util';

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
                //ciphers: 'SSLv3',
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
            pool: true,
            ignoreTLS: false,
            requireTLS: false,
            tls: {
                //ciphers: 'SSLv3',
                minVersion: 'TLSv1',
                //enableTrace: true,
                rejectUnauthorized: false,
            },
            debug: true



        }
        if (this.host)
            options.host = this.host;
        if (this.port)
            options.port = Number(this.port);
        if (this.user && this.pass) {
            options.auth = {
                user: this.user,
                pass: this.pass,
                //method: 'LOGIN'
            }
        }

        //for making clone
        let cloned = JSON.parse(JSON.stringify(options));
        if (cloned?.auth?.pass)
            cloned.auth.pass = 'somepassword';
        logger.info(cloned);
        this.transporter = nodemailer.createTransport(options);
    }
}


class AWSAccount extends EmailSender {


    constructor(private name: string, private fromName: string,
        private accessKey: string, private secretKey: string, private region?: string) {
        super();


        const ses = new aws.SES({
            apiVersion: "2010-12-01",
            region: this.region,
            credentials: {
                accessKeyId: this.accessKey,
                secretAccessKey: this.secretKey
            }
        });

        // create Nodemailer SES transporter
        this.transporter = nodemailer.createTransport({
            SES: { ses, aws },
        });

    }

}

class FerrumDome extends EmailSender {
    constructor(private name: string, private domain: string,
        private user: string, private pass: string, private url: string) {
        super();
        this.transporter = {
            sendMail: (mailOptions: any, callback: any) => {
                let options: AxiosRequestConfig = {
                    timeout: 5000,
                    headers: {
                        DomeApiKey: this.user + this.pass
                    }
                };
                const url = `${this.url}/api/cloud/email`;
                logger.info(`sending email over ${url}`);
                Axios.post(url, {
                    from: `no-reply@${domain}`,
                    to: mailOptions.to,
                    cc: mailOptions.cc,
                    subject: mailOptions.subject,
                    text: mailOptions.text,
                    html: mailOptions.html,
                    attachments: mailOptions.attachments ? mailOptions.attachments.map((x: any) => { return { filename: x.filename, content: x.content.toString('base64') } }) : undefined
                }, options)
                    .then((res) => {
                        callback(null, res.data);
                    }).catch((err) => {
                        callback(err, null);
                    });

            }
        }
    }

}


/**
 * @summary email sending business
 */
export class EmailService {
    protected sender: EmailSender | null;
    constructor(private configService: ConfigService) {
        this.sender = null;

    }
    async reset() {
        this.sender = null;
    }
    async send(email: Email) {
        const EmailSetting = await this.configService.getEmailSetting();
        if (EmailSetting.type == 'empty')// if any settings does not exits
            return;
        if (!this.sender) {

            switch (EmailSetting.type) {
                case 'google':
                    this.sender = new GmailAccount("gmail", EmailSetting.fromname, EmailSetting.user, EmailSetting.pass);
                    break;
                case 'office365':
                    this.sender = new Office365Account("office", EmailSetting.fromname, EmailSetting.user, EmailSetting.pass);
                    break;
                case 'smtp':
                    this.sender = new SmtpAccount('smtp', EmailSetting.fromname, EmailSetting.host || 'localhost', EmailSetting.port || 25, EmailSetting.isSecure || false, EmailSetting.user, EmailSetting.pass);
                    break;
                case 'aws':
                    this.sender = new AWSAccount('aws', EmailSetting.fromname, EmailSetting.accessKey, EmailSetting.secretKey, EmailSetting.region);
                    break;
                case 'ferrum':
                    const url = await this.configService.getUrl();
                    const domain = Util.extractDomainFrom(url) || '';
                    this.sender = new FerrumDome('ferrum', domain, EmailSetting.user, EmailSetting.pass, EmailSetting.url);
                    break;

                default:
                    logger.fatal(`unknown email type`);
                    throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "empty configuration");
            }

        }
        let tmp = {
            from: { name: EmailSetting.fromName, address: EmailSetting.user },
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
                    reject(new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodesInternal.ErrEmailSend, "email sending failed"))
                } else {
                    logger.info(`email sended to: ${email.to} subject: ${email.subject}`);
                    resolve(info.messageId);
                }
            })

        })
    }

    async sendWith(email: Email, EmailSetting: EmailSetting, pureError = false) {

        if (EmailSetting.type == 'empty')// if any settings does not exits
            return;
        let sender: EmailSender;

        switch (EmailSetting.type) {
            case 'google':
                sender = new GmailAccount("gmail", EmailSetting.fromname, EmailSetting.user, EmailSetting.pass);
                break;
            case 'office365':
                sender = new Office365Account("office", EmailSetting.fromname, EmailSetting.user, EmailSetting.pass);
                break;
            case 'smtp':
                sender = new SmtpAccount('smtp', EmailSetting.fromname, EmailSetting.host || 'localhost', EmailSetting.port || 25, EmailSetting.isSecure || false, EmailSetting.user, EmailSetting.pass);
                break;
            case 'aws':
                sender = new AWSAccount('aws', EmailSetting.fromname, EmailSetting.accessKey, EmailSetting.secretKey, EmailSetting.region);
                break;
            case 'ferrum':
                const url = await this.configService.getUrl();
                const domain = Util.extractDomainFrom(url) || '';
                sender = new FerrumDome('ferrum', domain, EmailSetting.user, EmailSetting.pass, EmailSetting.url);
                break;
            default:
                logger.fatal(`unknown email type`);
                throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "empty configuration");
        }


        let tmp = {
            from: { name: EmailSetting.fromName, address: EmailSetting.user },
            to: email.to,
            cc: email.cc,
            bcc: email.bcc,
            subject: email.subject,
            text: email.text,
            html: email.html,
            attachments: email.attachments ? email.attachments.map(x => { return { filename: x.filename, content: Buffer.from(x.content, 'base64') } }) : undefined

        }
        await new Promise((resolve, reject) => {
            sender?.transporter.sendMail(tmp, function (err: any, info: any) {
                if (err) {
                    logger.error(err.stack);
                    if (pureError)
                        reject(err)
                    else
                        reject(new RestfullException(500, ErrorCodes.ErrInternalError, ErrorCodesInternal.ErrEmailSend, "email sending failed"))
                } else {
                    logger.info(`email sended to: ${email.to} subject: ${email.subject}`);
                    resolve(info.messageId);
                }
            })

        })
    }
}
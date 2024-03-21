import chai from 'chai';
import chaiHttp from 'chai-http';
import { ConfigService } from '../src/service/configService';
import { Email, EmailService } from '../src/service/emailService';
import { EmailSetting } from '../src/model/emailSetting';
import { Util } from '../src/util';

chai.use(chaiHttp);
const expect = chai.expect;

describe('emailService ', async () => {

    beforeEach(async () => {

    })
    it.skip('send email through gmail', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        let config = new ConfigService('wt99Z3MDQgdTSQKU1gfzZkBLkUN2PBMLFtR0vjCSjlYvSq9U', filename)
        config.setEmailSetting({ fromname: 'ferrumgate', type: 'google', user: 'ferrumgates@gmail.com', pass: 'nqquxankumksakon' });
        const emailService = new EmailService(config);
        const email: Email = {
            subject: `test ${new Date().toISOString()}`, to: 'hamza@hamzakilic.com', text: `test ${new Date().toISOString()}`
        }

        await emailService.send(email);

    }).timeout(5000);

    it.skip('send email with gmail', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        let config = new ConfigService('wt99Z3MDQgdTSQKU1gfzZkBLkUN2PBMLFtR0vjCSjlYvSq9U', filename)
        const settings: EmailSetting = {
            fromname: 'ferrumgate',
            type: 'google', user: 'ferrumgates@gmail.com',
            pass: 'nqquxankumksakon'
        };
        config.setEmailSetting(settings);

        const emailService = new EmailService(config);
        const email: Email = {
            subject: `test sendWith ${new Date().toISOString()}`, to: 'hamza@hamzakilic.com', text: `test ${new Date().toISOString()}`
        }

        await emailService.sendWith(email, settings);

    }).timeout(5000);

    it.skip('send email with aws', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        let config = new ConfigService('wt99Z3MDQgdTSQKU1gfzZkBLkUN2PBMLFtR0vjCSjlYvSq9U', filename)
        const settings: EmailSetting = {
            fromname: 'no-reply ferrumote',
            type: 'aws',
            user: 'no-reply@ferrumote.com',
            pass: '',
            accessKey: 'AKIAUKD576YHOBCJYNX5',
            secretKey: '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',
            region: 'eu-north-1'

        };
        config.setEmailSetting(settings);

        const emailService = new EmailService(config);
        const email: Email = {
            subject: `test sendWith ${new Date().toISOString()}`, to: 'admin@ferrumote.com', text: `test ${new Date().toISOString()}`
        }

        await emailService.sendWith(email, settings);

    }).timeout(5000);

    it('send email with smtp', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        let config = new ConfigService('wt99Z3MDQgdTSQKU1gfzZkBLkUN2PBMLFtR0vjCSjlYvSq9U', filename)
        const settings: EmailSetting = {
            fromname: 'no-reply ferrumote',
            type: 'smtp',
            user: 'no-reply@ferrumote.com',
            pass: '',
            host: 'localhost',
            port: '2525',
            isSecure: true,

        };
        config.setEmailSetting(settings);

        const emailService = new EmailService(config);
        const email: Email = {
            subject: `test sendWith ${new Date().toISOString()}`, to: 'admin@ferrumote.com', text: `test ${new Date().toISOString()}`
        }

        await emailService.sendWith(email, settings);

    }).timeout(5000);

})


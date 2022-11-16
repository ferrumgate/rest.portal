
import chai from 'chai';
import chaiHttp from 'chai-http';
import { ConfigService } from '../src/service/configService';
import { Email, EmailService } from '../src/service/emailService';
import { EmailSettings } from '../src/model/emailSettings';
import { Util } from '../src/util';



chai.use(chaiHttp);
const expect = chai.expect;




describe.skip('emailService ', async () => {

    beforeEach(async () => {

    })
    it('send email through gmail', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        let config = new ConfigService('wt99Z3MDQgdTSQKU1gfzZkBLkUN2PBMLFtR0vjCSjlYvSq9U', filename)
        config.setEmailSettings({ fromname: 'ferrumgate', type: 'google', user: 'ferrumgates@gmail.com', pass: 'nqquxankumksakon' });
        const emailService = new EmailService(config);
        const email: Email = {
            subject: `test ${new Date().toISOString()}`, to: 'hamza@hamzakilic.com', text: `test ${new Date().toISOString()}`
        }

        await emailService.send(email);



    }).timeout(5000);

    it('send email with gmail', async () => {
        const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
        let config = new ConfigService('wt99Z3MDQgdTSQKU1gfzZkBLkUN2PBMLFtR0vjCSjlYvSq9U', filename)
        const settings: EmailSettings = {
            fromname: 'ferrumgate',
            type: 'google', user: 'ferrumgates@gmail.com',
            pass: 'nqquxankumksakon'
        };
        config.setEmailSettings(settings);

        const emailService = new EmailService(config);
        const email: Email = {
            subject: `test sendWith ${new Date().toISOString()}`, to: 'hamza@hamzakilic.com', text: `test ${new Date().toISOString()}`
        }

        await emailService.sendWith(email, settings);



    }).timeout(5000);

})



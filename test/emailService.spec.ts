
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { InputService } from '../src/service/inputService';
import { RestfullException } from '../src/restfullException';
import { ErrorCodes } from '../src/restfullException';
import { ConfigService } from '../src/service/configService';
import { Email, EmailService } from '../src/service/emailService';



chai.use(chaiHttp);
const expect = chai.expect;




describe.skip('emailService ', async () => {

    beforeEach(async () => {

    })
    it('send email through gmail', async () => {
        let config = new ConfigService('wt99Z3MDQgdTSQKU1gfzZkBLkUN2PBMLFtR0vjCSjlYvSq9U')
        config.setEmailOptions({ fromname: 'ferrumgate', type: 'google', user: 'ferrumgates@gmail.com', pass: '}Q]@c836}7$F+AwK' });
        const emailService = new EmailService(config);
        const email: Email = {
            subject: `test ${new Date().toISOString()}`, to: 'hamza@hamzakilic.com', text: `test ${new Date().toISOString()}`
        }

        await emailService.send(email);



    }).timeout(5000);

})



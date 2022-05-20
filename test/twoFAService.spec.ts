
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { InputService } from '../src/service/inputService';
import { RestfullException } from '../src/restfullException';
import { ErrorCodes } from '../src/restfullException';
import { CaptchaService } from '../src/service/captchaService';
import { ConfigService } from '../src/service/configService';
import { TwoFAService } from '../src/service/twofaService';



chai.use(chaiHttp);
const expect = chai.expect;




describe('twoFAService ', async () => {


    beforeEach(async () => {

    })

    it('generateSecret works', async () => {

        const service = new TwoFAService();
        const secret = service.generateSecret();
        expect(secret).exist;
        const token = service.generateToken(secret);
        expect(token).exist;

        const result = service.verifyToken(secret, token || '');
        expect(result).to.be.true;


    }).timeout(5000);

    it('verifyToken throws exception', async () => {

        const service = new TwoFAService();
        const secret = service.generateSecret();
        expect(secret).exist;
        const token = service.generateToken(secret);
        expect(token).exist;
        let isError = false;
        try {
            const result = service.verifyToken(secret, 'blaclaa');

        } catch (err) {
            isError = true;
        }
        expect(isError).to.be.true;


    }).timeout(5000);

})



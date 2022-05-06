
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { InputService } from '../src/service/inputService';
import { RestfullException } from '../src/restfullException';
import { ErrorCodes } from '../src/restfullException';



chai.use(chaiHttp);
const expect = chai.expect;




describe('captchaService ', async () => {

    beforeEach(async () => {

    })
    it('checkPasswordPolicy throws error', (done) => {

        done();

    }).timeout(5000);

})



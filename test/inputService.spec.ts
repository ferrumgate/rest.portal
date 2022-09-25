
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




describe('inputService ', async () => {

    beforeEach(async () => {

    })
    it('checkPasswordPolicy throws error', (done) => {
        const inputService = new InputService();
        let error = false;
        try {
            expect(inputService.checkPasswordPolicy('abc'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.true;

        error = false;
        try {
            expect(inputService.checkPasswordPolicy('abcDeDewa'));
        }
        catch (ignore) {
            error = true;
        }
        expect(error).to.be.true;
        done();

    }).timeout(5000);


    it('checkPasswordPolicy meets requirements', (done) => {
        const inputService = new InputService();
        let error = false;
        try {
            expect(inputService.checkPasswordPolicy('abcDeas399as'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.false
        done();

    }).timeout(5000);

    it('checkEmail ', (done) => {
        const inputService = new InputService();
        let error = false;
        try {
            expect(inputService.checkEmail('abdd'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.true;


        error = false;
        try {
            expect(inputService.checkEmail('abdd@yahoo.com'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.false;
        done();

    }).timeout(5000);


    it('checkCidr ', (done) => {
        const inputService = new InputService();
        let error = false;
        try {
            expect(inputService.checkCidr('10.0.0.1'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.true;


        error = false;
        try {
            expect(inputService.checkCidr('10.0.0.1/34'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.true;

        error = false;
        try {
            expect(inputService.checkCidr('10.0.0.1/24'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.false;
        done();

    }).timeout(5000);


    it('checkDomain ', (done) => {
        const inputService = new InputService();
        let error = false;
        try {
            expect(inputService.checkDomain('localhost'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.true;


        error = false;
        try {
            expect(inputService.checkDomain('ferrumgate.local'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.false;

        done();

    }).timeout(5000);

    it('checkUrl ', (done) => {
        const inputService = new InputService();
        let error = false;
        try {
            expect(inputService.checkUrl('secure.ferrumgate.local'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.true;


        error = false;
        try {
            expect(inputService.checkUrl('https://secure.ferrumgate.local'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.false;

        done();

    }).timeout(5000);



})



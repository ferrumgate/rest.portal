
import chai from 'chai';
import chaiHttp from 'chai-http';
import { InputService } from '../src/service/inputService';



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


    it('checkIp ', (done) => {
        const inputService = new InputService();
        let error = false;

        let result = inputService.checkIp('10.0.0.1', false)
        expect(result).to.be.true;

        let result2 = inputService.checkIp('::1', false)
        expect(result2).to.be.true;

        let result3 = inputService.checkIp('10.0.1', false)
        expect(result3).to.be.false;

        let result4 = inputService.checkIp('10.0.0.1/24', false)
        expect(result4).to.be.false;
        done();


    }).timeout(5000);


    it('checkDomain ', (done) => {
        const inputService = new InputService();
        let error = false;
        try {
            expect(inputService.checkDomain('https://localhost'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.true;


        error = false;
        try {
            expect(inputService.checkDomain('ferrumgate.zero'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.false;

        error = false;
        try {
            expect(inputService.checkDomain('ferrumgate'));
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
            expect(inputService.checkUrl('secure.ferrumgate.zero'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.true;


        error = false;
        try {
            expect(inputService.checkUrl('https://secure.ferrumgate.zero'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.false;

        done();

    }).timeout(5000);


    it('checkHost ', (done) => {
        const inputService = new InputService();
        let error = false;
        try {
            expect(inputService.checkHost('secure.ferrumgate.zero'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.false;


        error = false;
        try {
            expect(inputService.checkHost('https://secure.ferrumgate.zero'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.true;


        error = false;
        try {
            expect(inputService.checkHost('secure.ferrumgate.zero:123'));
        } catch (ignore) {
            error = true;
        }
        expect(error).to.be.false;

        done();

    }).timeout(5000);



})



import chai from 'chai';
import chaiHttp from 'chai-http';
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


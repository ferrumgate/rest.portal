
import chai from 'chai';
import chaiHttp from 'chai-http';
import { PingService } from '../src/service/pingService';


chai.use(chaiHttp);
const expect = chai.expect;

// this class is container for other classes
describe('pingService', async () => {

    beforeEach((done) => {

        done();
    })

    it('ping', async () => {
        const ping = new PingService();
        const response = await ping.ping('www.google.com', 10, 3);
        expect(response.alive).to.be.true;

    }).timeout(50000);


});
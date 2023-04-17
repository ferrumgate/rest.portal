
import chai from 'chai';
import chaiHttp from 'chai-http';
import { EventBufferedExecutor } from '../src/service/appService';
import { Util } from '../src/util';


chai.use(chaiHttp);
const expect = chai.expect;

// this class is container for other classes
describe('appService', async () => {

    beforeEach((done) => {

        done();
    })

    it('eventBufferedExecutor', async () => {
        let a = 0;
        const buf = new EventBufferedExecutor(async () => {
            a++;
        });
        await buf.push('');
        await buf.push('');
        await buf.push('');

        await Util.sleep(2000);
        expect(a > 0).to.be.true;

    }).timeout(50000);


});
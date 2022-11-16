
import chai from 'chai';
import chaiHttp from 'chai-http';
import { CaptchaService } from '../src/service/captchaService';
import { ConfigService } from '../src/service/configService';
import { Util } from '../src/util';



chai.use(chaiHttp);
const expect = chai.expect;




describe('captchaService ', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const configService = new ConfigService('mn4xq0zeryusnagsdkbb2a68r7uu3nn25q4i91orj3ofkgb42d6nw5swqd7sz4fm', filename);
    beforeEach(async () => {
        configService.setCaptcha({ server: '6Lcw_scfAAAAAFKwZuGa9vxuFF7ezh8ZtsQazdS0' })
    })
    it('captchaService throws error', async () => {
        let isError = false;
        try {
            const captchaService = new CaptchaService(configService);
            await captchaService.check('test');
        } catch (ignored) {
            isError = true;
        }
        expect(isError).to.be.true;


    }).timeout(5000);

})



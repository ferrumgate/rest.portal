
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { TemplateService } from '../src/service/templateService';
import { ConfigService } from '../src/service/configService';
import { Util } from '../src/util';
import { RedisService } from '../src/service/redisService';



chai.use(chaiHttp);
const expect = chai.expect;




describe('templateService', async () => {
    const filename = `/tmp/${Util.randomNumberString()}config.yaml`;
    const configService = new ConfigService('kgWn7f1dtNOjuYdjezf0dR5I3HQIMNrGsUqthIsHHPoeqt', filename);
    const redisService = new RedisService();
    before(async () => {
        await configService.setLogo({ default: fs.readFileSync('./src/service/templates/logo.txt').toString() });
        await configService.saveConfigToFile();
        await configService.loadConfigFromFile();
    })
    beforeEach(async () => {
        await redisService.flushAll();
    })
    it('createEmailConfirmation', async () => {

        const templateService = new TemplateService(configService);
        const logopath = (await configService.getLogo()).defaultPath || 'logo.png';
        const template = await templateService.createEmailConfirmation('hamza', 'https://portal.ferrumgate.com/user/confirmemail?key=9sTVrjfbhA0iI15qVi8a7HXIXDtUg22VHTJt3Z9s8XXlqAH5', logopath);
        fs.writeFileSync('/tmp/template1.html', template);
        expect(template).exist;

    }).timeout(5000);

    it('createForgotPassword', async () => {

        const templateService = new TemplateService(configService);
        const logopath = (await configService.getLogo()).defaultPath || 'logo.png';
        const template = await templateService.createForgotPassword('hamza', 'https://portal.ferrumgate.com/user/confirmemail?key=9sTVrjfbhA0iI15qVi8a7HXIXDtUg22VHTJt3Z9s8XXlqAH5', logopath);
        fs.writeFileSync('/tmp/template2.html', template);
        expect(template).exist;

    }).timeout(5000);

    it('createInvite', async () => {

        const templateService = new TemplateService(configService);
        const logopath = (await configService.getLogo()).defaultPath || 'logo.png';
        const template = await templateService.createInvite('hamza', 'https://portal.ferrumgate.com/user/invite?key=9sTVrjfbhA0iI15qVi8a7HXIXDtUg22VHTJt3Z9s8XXlqAH5', logopath);
        fs.writeFileSync('/tmp/template3.html', template);
        expect(template).exist;

    }).timeout(5000);


})




import chai from 'chai';
import chaiHttp from 'chai-http';
import { EventBufferedExecutor } from '../src/service/appService';
import { Util } from '../src/util';
import { LetsEncryptService } from '../src/service/letsEncryptService';
import { ConfigService } from '../src/service/configService';
import { SystemLogService } from '../src/service/systemLogService';
import { RedisService } from '../src/service/redisService';
import { ExpressApp } from '../src';
import fs from 'fs';


const host = 'https://192.168.88.250:9200';
const user = 'elastic';
const pass = '123456';

chai.use(chaiHttp);
const expect = chai.expect;

// this class is container for other classes
describe('LetsEncryptService', async () => {
    const expressApp = new ExpressApp(5002);
    const configService = new ConfigService('fljvc7rm1xfo37imbu3ryc5mfbh9jpm5', `/tmp/${Util.randomNumberString()}`)
    const systemlog = new SystemLogService(new RedisService(), new RedisService(), Util.randomNumberString(32), 'testme');
    before(async () => {

        await expressApp.start();
        if (fs.existsSync('/tmp/config.yaml'))
            fs.rmSync('/tmp/config.yaml')
        await configService.setConfigPath('/tmp/config.yaml');
        await configService.init();
        await configService.setES({ host: host, user: user, pass: pass });

    })

    beforeEach((done) => {

        done();
    })


    it('parse', async () => {

        const output = `Saving debug log to /tmp/acmelog/letsencrypt.log
        Plugins selected: Authenticator manual, Installer None
        Obtaining a new certificate
        Performing the following challenges:
        http-01 challenge for test.ferrumgate.com
        
        - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        Create a file containing just this data:
        
        h6eR60tMfe9bSngoRhoGYhcI8nucC4K8964F8V1_6oo.7yYpMMEOzCm3TJVd2vJQH5U6Lj7g91gZs_vdBBcLIi4
        
        And make it available on your web server at this URL:
        
        http://test.ferrumgate.com/.well-known/acme-challenge/h6eR60tMfe9bSngoRhoGYhcI8nucC4K8964F8V1_6oo
        
        - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        Press Enter to Continue`
        const folder = `/tmp/${Util.randomNumberString()}`
        const lets = new LetsEncryptService(configService, systemlog, folder);
        const result = await lets.parseChallenge(output, folder);
        expect(result?.key).to.equal('h6eR60tMfe9bSngoRhoGYhcI8nucC4K8964F8V1_6oo');
        expect(result?.value).to.equal('h6eR60tMfe9bSngoRhoGYhcI8nucC4K8964F8V1_6oo.7yYpMMEOzCm3TJVd2vJQH5U6Lj7g91gZs_vdBBcLIi4');


    }).timeout(50000);


    //for testing below tests
    //run before
    // docker run --net=host  -e "PEBBLE_VA_NOSLEEP=1" letsencrypt/pebble

    it('createCertificate will throw challenge error', async () => {


        const folder = `/tmp/acme-challegence`
        const lets = new LetsEncryptService(configService, systemlog, folder);
        let errorOccured = false;
        try {
            const result = await lets.createCertificate('local.ferrumgate.com', 'test@ferrumgate.com', 'http', 'https://localhost:14000/dir');
        } catch (err) {
            errorOccured = true;
        }
        expect(errorOccured).to.be.true;


    }).timeout(50000);


    it('createCertificate will return success', async () => {


        const folder = `/tmp/acme-challenge`
        const lets = new LetsEncryptService(configService, systemlog, folder);

        const result = await lets.createCertificate('local.ferrumgate.com', 'test@ferrumgate.com', 'http', 'https://localhost:14000/dir');
        expect(result.privateKey).exist;


    }).timeout(50000);

    it('renew will return success', async () => {


        const folder = `/tmp/acme-challenge`
        const lets = new LetsEncryptService(configService, systemlog, folder);

        const result = await lets.createCertificate('local.ferrumgate.com', 'test@ferrumgate.com', 'http', 'https://localhost:14000/dir');
        expect(result.privateKey).exist;

        const result2 = await lets.renew('local.ferrumgate.com', 'test@ferrumgate.com', 'https://localhost:14000/dir');
        expect(result2.privateKey).exist;
        expect(result.privateKey != result2.privateKey).to.be.true;


    }).timeout(50000);



});
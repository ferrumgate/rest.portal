
import chai from 'chai';
import chaiHttp from 'chai-http';
import { ConfigService } from '../src/service/configService';
import { RedisService } from '../src/service/redisService';

import { PKIService } from '../src/service/pkiService';
import { RedisConfigService } from '../src/service/redisConfigService';
import { SystemLogService } from '../src/service/systemLogService';
import { Util } from '../src/util';
import fs from 'fs';


chai.use(chaiHttp);
const expect = chai.expect;

declare global {
    interface Date {
        addDays(days: number): Date;
    }
}
Date.prototype.addDays = function (days: number) {
    var date = new Date(this.valueOf());
    date.setDate(date.getDate() + days);
    return date;
}


describe('PKIService ', async () => {
    const encKey = 'u88aapisbdvmufeptows0a5l53sa1r3v';
    const redis = new RedisService();
    const redisStream = new RedisService();
    const systemlog = new SystemLogService(redis, redisStream, encKey, 'testme');
    const configService = new RedisConfigService(redis, redisStream, systemlog, encKey, 'testme2');
    PKIService.init();
    beforeEach(async () => {

        await redis.flushAll();
    })
    function readFileSync(path: string) {
        return fs.readFileSync(path).toString();
    }

    it('create CA', async () => {

        const result = await PKIService.createCertificate({
            common: 'ferrumgate', country: 'TR', isCA: true,
            hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5', serial: 100, notAfter: new Date().addDays(5), notBefore: new Date().addDays(-10),

            sans: [
                { type: 'domain', value: 'test.ferrumgate.com' },
                { type: 'email', value: 'dev@ferrumgate.com' },
                { type: 'ip', value: '192.168.1.0' },
                { type: 'ip', value: '2001:4860:4860::8888' },
            ]

        })
        const tmpDir = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(tmpDir);
        console.log(tmpDir);
        const privateKey = `${tmpDir}/private.key`;
        const publicCrt = `${tmpDir}/public.crt`;
        fs.writeFileSync(privateKey, PKIService.toPEM(result.privateKeyBuffer, 'PRIVATE KEY'));
        fs.writeFileSync(publicCrt, PKIService.toPEM(result.certificateBuffer, 'CERTIFICATE'));
        const output = await Util.exec(`openssl x509 -in ${publicCrt} -text -noout`) as string;
        expect(output.includes('Issuer: C = TR + CN = ferrumgate')).to.be.true;
        expect(output.includes('Subject: C = TR + CN = ferrumgate')).to.be.true;
        expect(output.includes('CA:TRUE, pathlen:3')).to.be.true;
        expect(output.includes('DNS:test.ferrumgate.com, email:dev@ferrumgate.com, IP Address:192.168.1.0, IP Address:2001:4860:4860:0:0:0:0:8888')).to.be.true;



        const prv = await PKIService.parsePrivateKey(readFileSync(privateKey), 'SHA-512', 'RSASSA-PKCS1-v1_5');
        expect(prv).exist;

        const certs = await PKIService.parseCertificate(readFileSync(publicCrt));
        expect(certs.length).to.equal(1);

        const subject = await PKIService.parseSubject(certs[0]);
        expect(subject['CN']).to.equal('ferrumgate');





    }).timeout(5000);


    it('create CA and sign ', async () => {

        const caResult = await PKIService.createCertificate(
            {
                common: 'ferrumgate', country: 'TR', isCA: true, sans: [],
                hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5', serial: 100, notAfter: new Date().addDays(5), notBefore: new Date().addDays(-10)
            })
        const tmpDir = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(tmpDir);
        console.log(tmpDir);
        const privateKey = `${tmpDir}/ca.key`;
        const publicCrt = `${tmpDir}/ca.crt`;
        fs.writeFileSync(privateKey, PKIService.toPEM(caResult.privateKeyBuffer, 'PRIVATE KEY'));
        fs.writeFileSync(publicCrt, PKIService.toPEM(caResult.certificateBuffer, 'CERTIFICATE'));
        const ca = await PKIService.parseCertificate(readFileSync(publicCrt));

        const intermediateResult = await PKIService.createCertificate(
            {
                common: 'ferrumgate intermediate', country: 'UK', isCA: true, sans: [],
                hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5', serial: 100000,
                notAfter: new Date().addDays(5), notBefore: new Date().addDays(-10),
                ca: {
                    certificate: readFileSync(publicCrt),
                    privateKey: readFileSync(privateKey),
                    hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5'
                }
            })

        const privateKey2 = `${tmpDir}/inter.key`;
        const publicCrt2 = `${tmpDir}/inter.crt`;
        fs.writeFileSync(privateKey2, PKIService.toPEM(intermediateResult.privateKeyBuffer, 'PRIVATE KEY'));
        fs.writeFileSync(publicCrt2, PKIService.toPEM(intermediateResult.certificateBuffer, 'CERTIFICATE'));
        const intermediate = await PKIService.parseCertificate(readFileSync(publicCrt2));

        const isVerified1 = await PKIService.verifyCertificate(readFileSync(publicCrt2), [], ca, []);
        console.log(isVerified1);
        expect(isVerified1.result).to.be.true;


        const userResult = await PKIService.createCertificate(
            {
                common: 'ferrumgate user', country: 'UK', sans: [],
                isCA: false, hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5', serial: 100000,
                notAfter: new Date().addDays(5), notBefore: new Date().addDays(-10),
                ca: {
                    certificate: readFileSync(publicCrt2),
                    privateKey: readFileSync(privateKey2),
                    hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5'
                }
            })

        const privateKey3 = `${tmpDir}/user.key`;
        const publicCrt3 = `${tmpDir}/user.crt`;
        fs.writeFileSync(privateKey3, PKIService.toPEM(userResult.privateKeyBuffer, 'PRIVATE KEY'));
        fs.writeFileSync(publicCrt3, PKIService.toPEM(userResult.certificateBuffer, 'CERTIFICATE'));
        const user = await PKIService.parseCertificate(readFileSync(publicCrt3));






        const isVerified2 = await PKIService.verifyCertificate(readFileSync(publicCrt3), intermediate, ca, []);

        expect(isVerified2.result).to.be.true;



    }).timeout(5000);








})



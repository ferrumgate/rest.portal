
import chai from 'chai';
import chaiHttp from 'chai-http';
import { ConfigService } from '../src/service/configService';
import { RedisService } from '../src/service/redisService';


import { RedisConfigService } from '../src/service/redisConfigService';
import { SystemLogService } from '../src/service/systemLogService';
import { Util } from '../src/util';
import fs from 'fs';
import { UtilPKI } from '../src/utilPKI';


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


describe('UtilPKI ', async () => {

    UtilPKI.init();
    beforeEach(async () => {


    })
    function readFileSync(path: string) {
        return fs.readFileSync(path).toString();
    }

    it.skip('create CA', async () => {

        const result = await UtilPKI.createCertificate({
            CN: 'ferrumgate', O: 'TR', isCA: true,
            hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5',
            serial: 100, notAfter: new Date().addDays(5), notBefore: new Date().addDays(-10),

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
        fs.writeFileSync(privateKey, UtilPKI.toPEM(result.privateKeyBuffer, 'PRIVATE KEY'));
        fs.writeFileSync(publicCrt, UtilPKI.toPEM(result.certificateBuffer, 'CERTIFICATE'));
        const output = await Util.exec(`openssl x509 -in ${publicCrt} -text -noout`) as string;

        expect(output.includes('Issuer: O = TR + CN = ferrumgate')).to.be.true;
        expect(output.includes('Subject: O = TR + CN = ferrumgate')).to.be.true;
        expect(output.includes('CA:TRUE, pathlen:3')).to.be.true;
        expect(output.includes('DNS:test.ferrumgate.com, email:dev@ferrumgate.com, IP Address:192.168.1.0, IP Address:2001:4860:4860:0:0:0:0:8888')).to.be.true;



        const prv = await UtilPKI.parsePrivateKey(readFileSync(privateKey), 'SHA-512', 'RSASSA-PKCS1-v1_5');
        expect(prv).exist;

        const certs = await UtilPKI.parseCertificate(readFileSync(publicCrt));
        expect(certs.length).to.equal(1);

        const subject = await UtilPKI.parseSubject(certs[0]);
        expect(subject['CN']).to.equal('ferrumgate');





    }).timeout(5000);


    async function createCA(cn = 'ferrumgate', before = -10, after = 5) {
        const caResult = await UtilPKI.createCertificate(
            {
                CN: cn, O: 'TR', isCA: true, sans: [],
                hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5', serial: 100, notAfter: new Date().addDays(after), notBefore: new Date().addDays(before)
            })
        const tmpDir = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(tmpDir);
        console.log(tmpDir);
        const privateKey = `${tmpDir}/ca.key`;
        const publicCrt = `${tmpDir}/ca.crt`;
        fs.writeFileSync(privateKey, UtilPKI.toPEM(caResult.privateKeyBuffer, 'PRIVATE KEY'));
        fs.writeFileSync(publicCrt, UtilPKI.toPEM(caResult.certificateBuffer, 'CERTIFICATE'));
        const ca = await UtilPKI.parseCertificate(readFileSync(publicCrt));
        const crt = readFileSync(publicCrt);
        const key = readFileSync(privateKey);
        return { ca, crt, key }
    }
    async function createIntermediate(CAcrt: string, CAkey: string) {
        const intermediateResult = await UtilPKI.createCertificate(
            {
                CN: 'ferrumgate intermediate', O: 'UK', isCA: true, sans: [],
                hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5', serial: 100000,
                notAfter: new Date().addDays(5), notBefore: new Date().addDays(-10),
                ca: {
                    publicCrt: CAcrt,
                    privateKey: CAkey,
                    hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5'
                }
            })
        const tmpDir = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(tmpDir);
        console.log(tmpDir);
        const privateKey2 = `${tmpDir}/inter.key`;
        const publicCrt2 = `${tmpDir}/inter.crt`;
        fs.writeFileSync(privateKey2, UtilPKI.toPEM(intermediateResult.privateKeyBuffer, 'PRIVATE KEY'));
        fs.writeFileSync(publicCrt2, UtilPKI.toPEM(intermediateResult.certificateBuffer, 'CERTIFICATE'));
        const intermediate = await UtilPKI.parseCertificate(readFileSync(publicCrt2));
        const crt = readFileSync(publicCrt2);
        const key = readFileSync(privateKey2);
        return { intermediate, inCrt: crt, inKey: key }
    }


    it('create CA and sign ', async () => {


        const tmpDir = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(tmpDir);
        const { ca, crt, key } = await createCA();
        const { intermediate, inCrt, inKey } = await createIntermediate(crt, key);

        const isVerified1 = await UtilPKI.verifyCertificate(inCrt, [], ca, []);
        console.log(isVerified1);
        expect(isVerified1.result).to.be.true;


        const userResult = await UtilPKI.createCertificate(
            {
                CN: 'ferrumgate user', O: 'UK', sans: [],
                isCA: false, hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5', serial: 100000,
                notAfter: new Date().addDays(5), notBefore: new Date().addDays(-10),
                ca: {
                    publicCrt: inCrt,
                    privateKey: inKey,
                    hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5'
                }
            })

        const privateKey3 = `${tmpDir}/user.key`;
        const publicCrt3 = `${tmpDir}/user.crt`;
        fs.writeFileSync(privateKey3, UtilPKI.toPEM(userResult.privateKeyBuffer, 'PRIVATE KEY'));
        fs.writeFileSync(publicCrt3, UtilPKI.toPEM(userResult.certificateBuffer, 'CERTIFICATE'));
        const user = await UtilPKI.parseCertificate(readFileSync(publicCrt3));


        const isVerified2 = await UtilPKI.verifyCertificate(readFileSync(publicCrt3), intermediate, ca, []);

        expect(isVerified2.result).to.be.true;



    }).timeout(5000);



    /*  it('create CA and sign with old date and verity', async () => {
 
         const tmpDir = `/tmp/${Util.randomNumberString()}`;
         fs.mkdirSync(tmpDir);
         const { ca, crt, key } = await createCA();
 
         const { intermediate, inCrt, inKey } = await createIntermediate(crt, key);
 
         const userResult = await UtilPKI.createCertificate(
             {
                 CN: 'ferrumgate user', O: 'UK', sans: [],
                 isCA: false, hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5', serial: 100000,
                 notAfter: new Date().addDays(-5), notBefore: new Date().addDays(-10),//invalid date test
                 ca: {
                     publicCrt: crt,
                     privateKey: inKey,
                     hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5'
                 }
             })
 
         const privateKey3 = `${tmpDir}/user.key`;
         const publicCrt3 = `${tmpDir}/user.crt`;
         fs.writeFileSync(privateKey3, UtilPKI.toPEM(userResult.privateKeyBuffer, 'PRIVATE KEY'));
         fs.writeFileSync(publicCrt3, UtilPKI.toPEM(userResult.certificateBuffer, 'CERTIFICATE'));
         const user = await UtilPKI.parseCertificate(readFileSync(publicCrt3));
 
 
         const isVerified2 = await UtilPKI.verifyCertificate(readFileSync(publicCrt3), intermediate, ca, []);
 
         expect(isVerified2.result).to.be.false;
 
 
 
     }).timeout(5000);
 
 
 
     it('multiple CA  multiple intermediate check', async () => {
 
         const tmpDir = `/tmp/${Util.randomNumberString()}`;
         fs.mkdirSync(tmpDir);
         const { ca, crt, key } = await createCA();
         const { intermediate, inCrt, inKey } = await createIntermediate(crt, key);
 
         const userResult = await UtilPKI.createCertificate(
             {
                 CN: 'ferrumgate user', O: 'UK', sans: [],
                 isCA: false, hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5', serial: 100000,
                 notAfter: new Date().addDays(5), notBefore: new Date().addDays(-10),
                 ca: {
                     publicCrt: inCrt,
                     privateKey: inKey,
                     hashAlg: 'SHA-512', signAlg: 'RSASSA-PKCS1-v1_5'
                 }
             })
 
         const privateKey3 = `${tmpDir}/user.key`;
         const publicCrt3 = `${tmpDir}/user.crt`;
         fs.writeFileSync(privateKey3, UtilPKI.toPEM(userResult.privateKeyBuffer, 'PRIVATE KEY'));
         fs.writeFileSync(publicCrt3, UtilPKI.toPEM(userResult.certificateBuffer, 'CERTIFICATE'));
         const user = await UtilPKI.parseCertificate(readFileSync(publicCrt3));
 
         const { ca: ca2, crt: crt2, key: key2 } = await createCA();
         const { intermediate: intermediate2, inCrt: inCrt2, inKey: inKey2 } = await createIntermediate(crt2, key2);
 
         //ca ,intermedidate, ca2,intermediate2
         const isVerified2 = await UtilPKI.verifyCertificate(readFileSync(publicCrt3), intermediate.concat(intermediate2), ca.concat(ca2), []);
         expect(isVerified2.result).to.be.true;
 
         // intermediate2 ,ca
         const isVerified3 = await UtilPKI.verifyCertificate(readFileSync(publicCrt3), intermediate2, ca, []);
         expect(isVerified3.result).to.be.false;
 
 
 
     }).timeout(5000);
 
 
 
 
     it('create CA with openssl', async () => {
 
         const result = await Util.createSelfSignedCrt('ferrumgate.test', '10')
 
 
         const prv = await UtilPKI.parsePrivateKey(result.privateKey, 'SHA-512', 'RSASSA-PKCS1-v1_5');
         expect(prv).exist;
 
         const certs = await UtilPKI.parseCertificate(result.publicCrt);
         expect(certs.length).to.equal(1);
 
         const subject = await UtilPKI.parseSubject(certs[0]);
         expect(subject['CN']).to.equal('ferrumgate.test');
 
 
     }).timeout(5000);
 
     it('createP12_2', async () => {
 
         const tmpDir = `/tmp/${Util.randomNumberString()}`;
         fs.mkdirSync(tmpDir);
         console.log(tmpDir);
         const { ca, crt, key } = await createCA();
         const { intermediate, inCrt, inKey } = await createIntermediate(crt, key);
         const fileBuffer = await UtilPKI.createP12_2(inKey, inCrt, crt, '123456');
         //fs.writeFileSync('/tmp/abo.p12', fileBuffer);
     })
 
     it('createP12', async () => {
 
         const tmpDir = `/tmp/${Util.randomNumberString()}`;
         fs.mkdirSync(tmpDir);
         console.log(tmpDir);
         const { ca, crt, key } = await createCA();
         const { intermediate, inCrt, inKey } = await createIntermediate(crt, key);
         const fileBuffer = await UtilPKI.createP12(inKey, inCrt, '123456',);
         //fs.writeFileSync('/tmp/abo1.p12', fileBuffer);
     })
 
  */




})



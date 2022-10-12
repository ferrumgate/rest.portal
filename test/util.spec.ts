
import chai from 'chai';
import chaiHttp from 'chai-http';
import { Util } from '../src/util';
import fs from 'fs';
import del from 'del';
import nock from 'nock';
import fspromise from 'fs/promises';



chai.use(chaiHttp);
const expect = chai.expect;


const token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVzIjoxNTU0MDExMjc4NzU5LCJ1c2VyIjp7ImlkIjoiNzQwIn0sImNsaWVudCI6eyJpZCI6ImlmIHlvdSBzZWUgbWUifSwiaXNzIjoib2F1dGgyc2VydmljZSIsInR5cGUiOiJhY2Nlc3MiLCJpYXQiOjE1NTQwMDc2Nzh9.j5B85up9q0gNrjxS8IhzYA7_X6wnwAM0tNSkXNK2Zz6BUt1gL0DqWg-l39CThmSWSInkjoV4d1YopXW8n2uaUmY1j0vldee49S_Cma7BDcmSoU0k_wkYqYlqUXa0G3KF0PAjnKOHFTWp3in4m0fT3BRtCFYQVeqhz11wVCIMGclaN8rmW5FrqJ6TzhyIjsySyRNEBd7Es-GyM9ngxLcB1KXJj2SCVTuwLPP7B8WLoxSkZNDTIBU3sh2hqwFGfYUJ8hHq2xY5HYlxGt8zlDggWGBYVTIs2ADQTtPzQ3_WM_n3zx27dkNNqM2HDrh73NFI27_9nTeUp18aepSm9fLbyA";
const key = `-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIJAJRd78FfMuiPMA0GCSqGSIb3DQEBCwUAMDoxGzAZBgNV
BAMMEnJlc3QtY29uZmlnLWFjY2VzczEbMBkGA1UECgwScmVzdC1jb25maWctYWNj
ZXNzMB4XDTE5MDMzMDA5MTMwOFoXDTI5MDMyNzA5MTMwOFowOjEbMBkGA1UEAwwS
cmVzdC1jb25maWctYWNjZXNzMRswGQYDVQQKDBJyZXN0LWNvbmZpZy1hY2Nlc3Mw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfGOFz5u/8WXcRiLWf+Io6
O/F2Re9ubWcckqteFB9XkjW6G+VkVqYAX7mkfGV2SqMQbrfUkq9Kp0zT7XXXlEAO
DjnTa4zeWgSD5y4OcjvF0+qAfyBfkwc+9zEn7qE6AvKJ42YNzVhfrurKrglWCwyB
tDmQBl/+99XJbr4wkNhG1B8nZY7N8/cqvY7OmfdsCXeIT+iqeMCK8Em4mc9d3Uab
tou9w5BkToU0kx0C7HZOngisOCa5TQK2bnjncwG4AswjQx7BUFKDi+R6YD0fViAn
YJk2FJwJ9nNSNTs37uvBBDAFdqzmYwTcQx/0gXHSelfMLwDq9A9gHdhu6EWFIwh/
AgMBAAGjUDBOMB0GA1UdDgQWBBQiwMfhRostlFTpgWFghSGcyct7pDAfBgNVHSME
GDAWgBQiwMfhRostlFTpgWFghSGcyct7pDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQAXb+0FxgJlB3wMHGqaYCZMD6GmPARnW3EmkSwcVZHiPyGR3tbu
0VgTZgK49YRV0lpb4qiqn8W3Hn2xXlKejxNLUcvWASIpMFz+PrnmSzDvc3nxDKjR
qEslIcSIPuPMOyLmQIcqH2/VpX4F9MQ0pa0mb6I6S4otso6QPKR+Xq5FiQUxP2zG
TCvvn2OEO8wE2l6UmI5RBb0MmskEi70j92bYopkX3wqoG3UU7vIFcq3O8CEDvwCS
tM2n40gqO9g0+ygE0cOOYXKUcCJv9tDeobq62D5PBrxSsQ+cIISUO3vVFk5s6KZe
5kxF0zUuJ425UyB74+HYlSUo5VcWrPao2dUK
-----END CERTIFICATE-----
`
describe('util ', () => {

    before(async () => {
        const scope = nock('http://ferrumgate.com').persist()
            .get('/test.zip')
            .replyWithFile(200, __dirname + '/data/test.zip', {
                'Content-Type': 'text/plain',
            })

    })
    /* it('must verify', (done) => {
        Util.verifyJwt(token, key);
        done();

    }); */
    /* it('must not verify', (done) => {
        try {

            Util.verifyJwt(token, key.slice(0, key.length - 10));
            done(new Error('must throw exception'));

        } catch (err) {
            done();
        }


    }); */

    it('hash must create', (done) => {

        let hash16 = Util.createRandomHash(16) as string;
        expect(hash16.length).to.equal(16);

        let hash8 = Util.createRandomHash(8) as string;
        expect(hash8.length).to.equal(8);
        done();



    });


    it('random number string must be 6 or 7 length', (done) => {
        let save = process.env.NODE_ENV;
        process.env.NODE_ENV = '';
        let random = Util.randomNumberString(6) as String;
        expect(random.length).to.equal(6);

        let random2 = Util.randomNumberString(7);
        expect(random2.length).to.equal(7);
        for (const iterator of random2) {
            var chars = "0123456789abcdefghiklmnopqrstuvwxyzABCDEFGHIKLMNOPQRSTUVWXYZ";
            let founded = false;
            for (const iterator2 of chars) {
                if (iterator2 == iterator) {
                    founded = true;
                    break;
                }

            }
            expect(founded).to.be.true;
        }
        done();
        process.env.NODE_ENV = save;



    });

    it('password hash must be true', (done) => {
        let password = 'deneme';
        let hash = '$2b$10$szpr23eWIlYpRINKCFC4zOrWs6/iR7DiUUdTFjoPn7hZYYcZgLCji';
        let issame = Util.bcryptCompare(password, hash);
        expect(issame).to.equal(true);

        done();
    })


    it('password hash create', (done) => {
        let password = 'deneme';

        let hash = Util.bcryptHash(password);
        expect(hash.startsWith("$2b")).to.equal(true);

        done();
    })




    it('downloadFile', async () => {



        let tmpFolder = `/tmp/${Util.randomNumberString()}`;
        if (fs.existsSync(tmpFolder))
            del.sync(tmpFolder, { force: true });
        fs.mkdirSync(tmpFolder);
        let path = tmpFolder + '/' + Util.randomNumberString() + '.zip'
        await Util.downloadFile('http://ferrumgate.com/test.zip', path);
        expect(fs.existsSync(path)).to.be.true;



    }).timeout(300000)

    it('extractZip', async () => {



        let tmpFolder = `/tmp/${Util.randomNumberString()}`;
        if (fs.existsSync(tmpFolder))
            await del(tmpFolder, { force: true });
        fs.mkdirSync(tmpFolder);
        let path = tmpFolder + '/' + Util.randomNumberString() + '.zip'
        await Util.downloadFile('http://ferrumgate.com/test.zip', path);
        expect(fs.existsSync(path)).to.be.true;

        let tmpFolder2 = `${tmpFolder}/${Util.randomNumberString()}`;
        await Util.extractZipFile(path, tmpFolder2);
        expect(fs.existsSync(`${tmpFolder2}/test.txt`)).to.be.true;



    }).timeout(300000)

    it('zipFolder', async () => {



        let tmpFolder = `/tmp/${Util.randomNumberString()}`;
        if (fs.existsSync(tmpFolder))
            await del(tmpFolder, { force: true });
        fs.mkdirSync(tmpFolder);
        let path = tmpFolder + '/' + Util.randomNumberString() + '.txt'
        fs.writeFileSync(path, 'deneme');
        await Util.zipFolder(tmpFolder, '/tmp/test.zip');
        expect(fs.existsSync('/tmp/test.zip')).to.be.true;



    }).timeout(300000)


    it('ipToBigInt', (done) => {
        let ip = "81.214.130.220";
        let decimal = 1373012700;
        let result = Util.ipToBigInteger(ip);
        expect(result.toString()).to.be.equal(decimal.toString());

        let ipv6 = '2001:4860:4860::8888';
        let decimalbig6 = '42541956123769884636017138956568135816'
        let resultbig = Util.ipToBigInteger(ipv6);
        expect(resultbig.toString()).to.be.equal(decimalbig6.toString());

        done();

    });

    it('bigIntToIp', (done) => {
        let ip = "81.214.130.220";
        let decimal = 1373012700;
        let result = Util.bigIntegerToIp(BigInt(decimal));
        expect(result).to.be.equal(ip.toString());

        let ipv6 = '2001:4860:4860::8888';
        let decimalbig6 = '42541956123769884636017138956568135816'
        let resultbig = Util.bigIntegerToIp(BigInt(decimalbig6));
        expect(resultbig).to.be.equal('2001:4860:4860::8888');

        done();

    });


    it('ipRangeToCidr test mask 32', (done) => {
        let start = "95.10.150.157";
        let end = '95.10.150.157';
        let result = Util.ipRangeToCidr(start, end);
        expect(result).not.null;
        expect(result).not.undefined;
        expect(result?.baseIp).to.eq(start);
        expect(result?.mask).to.eq(32);

        done();

    });

    it('ipRangeToCidr test mask 24', (done) => {
        let start = "185.165.22.0";
        let end = '185.165.22.255';
        let result = Util.ipRangeToCidr(start, end);
        expect(result).not.null;
        expect(result).not.undefined;
        expect(result?.baseIp).to.eq(start);
        expect(result?.mask).to.eq(24);

        done();

    });

    it('ipRangeToCidr test mask 28', (done) => {
        let start = "91.93.178.16";
        let end = '91.93.178.31';
        let result = Util.ipRangeToCidr(start, end);
        expect(result).not.null;
        expect(result).not.undefined;
        expect(result?.baseIp).to.eq(start);
        expect(result?.mask).to.eq(28);

        done();

    });

    it('ipRangeToCidr test mask 16', (done) => {
        let start = "91.93.0.0";
        let end = '91.93.255.255';
        let result = Util.ipRangeToCidr(start, end);
        expect(result).not.null;
        expect(result).not.undefined;
        expect(result?.baseIp).to.eq(start);
        expect(result?.mask).to.eq(16);

        done();

    });

    it('ipRangeToCidr ipv6 test mask 28', (done) => {
        let start = "2001:4860:0000:0000:0000:0000:0000:0000";
        let end = '2001:486f:ffff:ffff:ffff:ffff:ffff:ffff';
        let result = Util.ipRangeToCidr(start, end);
        expect(result).not.null;
        expect(result).not.undefined;
        expect(result?.baseIp).to.eq(start);
        expect(result?.mask).to.eq(28);

        done();

    });

    it('ipCidrToRange ipv6 test mask 28', (done) => {
        let start = "2001:4860::";
        let end = '2001:486f:ffff:ffff:ffff:ffff:ffff:ffff';
        let result = Util.ipCidrToRange('2001:4860:4860::8888', 28);
        expect(result).not.null;
        expect(result).not.undefined;
        expect(result?.start).to.eq(start);
        expect(result?.end).to.eq(end);

        done();

    });

    it('ipCidrToRange test mask 16', (done) => {
        let start = "91.93.0.0";
        let end = '91.93.255.255';
        let result = Util.ipCidrToRange('91.93.0.0', 16);
        expect(result).not.null;
        expect(result).not.undefined;
        expect(result?.start).to.eq(start);
        expect(result?.end).to.eq(end);

        done();

    });


    it('ipCidrToRange test mask 28', (done) => {
        let start = "91.93.178.16";
        let end = '91.93.178.31';
        let result = Util.ipCidrToRange("91.93.178.16", 28);
        expect(result).not.null;
        expect(result).not.undefined;
        expect(result?.start).to.eq(start);
        expect(result?.end).to.eq(end);

        done();

    });

    it('ipCidrToRange test mask 32', (done) => {
        let start = "91.93.178.16";

        let result = Util.ipCidrToRange("91.93.178.16", 32);
        expect(result).not.null;
        expect(result).not.undefined;
        expect(result?.start).to.eq(start);
        expect(result?.end).to.eq(start);

        done();

    });

    it('islocalnetwork ', (done) => {
        let start = "91.93.178.16";
        let result = Util.isLocalNetwork("91.93.178.16");
        expect(result).to.be.false;
        result = Util.isLocalNetwork("10.0.0.1");
        expect(result).to.be.true;
        result = Util.isLocalNetwork("::1");
        expect(result).to.be.true;
        done();

    });

    it('encrypt ', (done) => {
        const str = 'DENEME';
        const encrypted = Util.encrypt('Et2vSy5Pa98o2wdc9HH2SyQXjRdEKsDI', str);
        expect(encrypted).to.equal('28cdbbf646f6fdb0a56704aba6105727');

        done();
    });

    it('decrypt ', (done) => {
        const str = '28cdbbf646f6fdb0a56704aba6105727';
        const encrypted = Util.decrypt('Et2vSy5Pa98o2wdc9HH2SyQXjRdEKsDI', str);
        expect(encrypted).to.equal('DENEME');

        done();
    });
    it('exec ', async () => {
        const output = await Util.exec("ls")
        expect(output).to.be.exist;//if output is not empty

    });

    it('createSelfSignedCrt ', async () => {
        const domain = `${Util.randomNumberString(8)}.com`;
        const output = await Util.createSelfSignedCrt(domain, '/tmp')
        expect(fs.existsSync(`/tmp/${domain}.crt`)).to.be.true
        expect(fs.existsSync(`/tmp/${domain}.key`)).to.be.true

    });




});
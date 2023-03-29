
import chai from 'chai';
import chaiHttp from 'chai-http';
import { Util } from '../src/util';
import fs from 'fs';

import nock from 'nock';
import IPCIDR from 'ip-cidr';
import crypto from 'crypto';



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
            fs.rmSync(tmpFolder, { recursive: true, force: true });
        fs.mkdirSync(tmpFolder);
        let path = tmpFolder + '/' + Util.randomNumberString() + '.zip'
        await Util.downloadFile('http://ferrumgate.com/test.zip', path);
        expect(fs.existsSync(path)).to.be.true;



    }).timeout(300000)

    it('extractZip', async () => {



        let tmpFolder = `/tmp/${Util.randomNumberString()}`;
        if (fs.existsSync(tmpFolder))
            fs.rmSync(tmpFolder, { recursive: true, force: true });
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
            fs.rmSync(tmpFolder, { recursive: true, force: true });
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


    it('isArrayElementExist ', async () => {
        expect(Util.isArrayElementExist(undefined, undefined)).to.be.false;
        expect(Util.isArrayElementExist(undefined, null as any)).to.be.false;
        expect(Util.isArrayElementExist(undefined, null as any)).to.be.false;
        expect(Util.isArrayElementExist('5' as any, '4' as any)).to.be.false;

        expect(Util.isArrayElementExist([1, 3, 4], [2, 3, 5])).to.be.true;
        expect(Util.isArrayElementExist([1, 3, 4], [5])).to.be.false;
        expect(Util.isArrayElementExist([1, 3, 4], ['4'])).to.be.false;

    });
    it('isUndefinedOrNull ', async () => {
        expect(Util.isUndefinedOrNull(undefined)).to.be.true;
        expect(Util.isUndefinedOrNull(null)).to.be.true;
        expect(Util.isUndefinedOrNull(0)).to.be.false;
        expect(Util.isUndefinedOrNull('')).to.be.false;


    });

    it('isArrayEqual ', async () => {
        expect(Util.isArrayEqual(undefined, undefined)).to.be.true;
        expect(Util.isArrayEqual(undefined, null as any)).to.be.true;
        expect(Util.isArrayEqual([0], [1])).to.be.false;
        expect(Util.isArrayEqual([0, 1], [0])).to.be.false;
        expect(Util.isArrayEqual([0], ['0'])).to.be.false;
        expect(Util.isArrayEqual([0, 1], [0, 1])).to.be.true;


    });


    it('createSelfSignedCrt ', async () => {
        const random = Util.randomNumberString();
        const domain = `${Util.randomNumberString(8)}.com`;
        const output = await Util.createSelfSignedCrt(domain, `/tmp/${random}`);
        expect(output.privateKey).exist;
        expect(output.publicKey).exist;
        expect(fs.existsSync(`/tmp/${random}/${domain}.crt`)).to.be.true
        expect(fs.existsSync(`/tmp/${random}/${domain}.key`)).to.be.true

    });

    it('createCASignedCrt ', async () => {
        const random = Util.randomNumberString();
        const cahostname = `${Util.randomNumberString(8)}.com`;
        const ca = await Util.createSelfSignedCrt(cahostname, `/tmp/${random}`);


        const domain = `${Util.randomNumberString(8)}.com`;
        const output = await Util.createCASignedCrt(domain, ca, `/tmp/${random}`);
        expect(output.privateKey).exist;
        expect(output.publicKey).exist;
        expect(fs.existsSync(`/tmp/${random}/${domain}.crt`)).to.be.true
        expect(fs.existsSync(`/tmp/${random}/${domain}.key`)).to.be.true

    });
    it('getCertificateInfo ', async () => {
        const cahostname = `cahost`;
        const ca = await Util.createSelfSignedCrt(cahostname);


        const domain = `test.com`;
        const output = await Util.createCASignedCrt(domain, ca);
        const x = await Util.getCertificateInfo(output.publicKey, ca.publicKey);
        expect(x.isValid).to.be.true;
        expect(x.remainingMS > 0);


        const cahostname2 = `cahost2`;
        const ca2 = await Util.createSelfSignedCrt(cahostname2);
        const x2 = await Util.getCertificateInfo(output.publicKey, ca2.publicKey);
        expect(x2.isValid).to.be.false;
        expect(x2.remainingMS > 0);




    }).timeout(120000);

    it('getCertificateInfo ', async () => {
        const cahostname = `cahost`;
        const ca = await Util.createSelfSignedCrt(cahostname);


        const domain = `test.com`;
        const output = await Util.createCASignedCrt(domain, ca);
        const x = await Util.getCertificateInfo(output.publicKey, ca.publicKey);
        expect(x.isValid).to.be.true;
        expect(x.remainingMS > 0);


        const cahostname2 = `cahost2`;
        const ca2 = await Util.createSelfSignedCrt(cahostname2);
        const x2 = await Util.getCertificateInfo(output.publicKey, ca2.publicKey);
        expect(x2.isValid).to.be.false;
        expect(x2.remainingMS > 0);




    }).timeout(120000);


    it('maskFileds ', async () => {
        const test = {
            id: '1',
            test: 'adfa'
        }

        const result = Util.maskFields({ ...test }, ['id']);
        expect(result.id).to.equal(test.id);
        expect(result.test).not.equal(test.test);


        const test2 = {
            ...test,
            bla: {
                id: '3',
                test: '4',
                nu: 54

            }

        }
        const result2 = Util.maskFields({ ...test2, bla: { ...test2.bla } });
        expect(result2.id).not.equal(test2.id);
        expect(result2.test).not.equal(test2.test);
        expect(result2.bla.id).not.equal(test2.bla.id);
        expect(result2.bla.test).not.equal(test2.bla.test);
        expect(result2.bla.nu).to.equal(0);




    }).timeout(120000);


    it('jencrypt ', (done) => {
        const str = 'DENEME';
        const encrypted = Util.jencrypt('Et2vSy5Pa98o2wdc9HH2SyQXjRdEKsDI', str);
        expect(encrypted.toString('hex')).to.equal('28cdbbf646f6fdb0a56704aba6105727');

        done();
    });

    it('jdecrypt ', (done) => {
        const str = '28cdbbf646f6fdb0a56704aba6105727';
        const encrypted = Util.jdecrypt('Et2vSy5Pa98o2wdc9HH2SyQXjRdEKsDI', Buffer.from(str, 'hex')).toString('utf-8');
        expect(encrypted).to.equal('DENEME');

        done();
    });

    it('jencode/jdecode ', (done) => {
        const val = {
            id: 1, name: 'string', arr: [1]
        }
        const json = Util.jencode(val);
        const val2 = Util.jdecode(json) as any;
        expect(val2.id).to.equal(1);
        expect(val2.name).to.equal('string');
        expect(val2.arr[0]).to.equal(1);


        done();
    });

    it('ipToHex', async () => {

        const hex = Util.ipToHex('192.168.1.1');
        expect(hex).to.equal('0x000000000000000000000000c0a80101');
        const hex2 = Util.ipToHex('2001:db8:3c4d::/48')
        expect(hex2).to.equal('0x20010db83c4d00000000000000000000');



    }).timeout(20000);


    it('cidrNormalize', async () => {

        const cidr = Util.cidrNormalize('192.168.1.2/24');

        expect(cidr).to.equal('192.168.1.0/24');

        const cidr6 = Util.cidrNormalize('2001:db8:85a3::8a2e:370:7336/64');
        expect(cidr6).to.equal('2001:db8:85a3::/64');



    }).timeout(20000);



    it('timeZoneList', () => {

        const timezones = Util.timeZoneList();
        expect(timezones.length > 0).to.be.true;
        const AmericaNewyork = timezones.find(x => x.name == 'America/New_York');
        expect(AmericaNewyork).exist;
        expect(AmericaNewyork?.offset == 240 || AmericaNewyork?.offset == 300).to.be.true;
    }).timeout(10000);


    it('timeInZone', () => {
        const date = Util.timeInZone('America/New_York', new Date('2023-02-19 13:05:02.0Z').getTime());
        expect(date.hour).to.equal(8);
        expect(date.minute).to.equal(5);
        expect(date.second).to.equal(2);
        expect(date.milisecond).to.equal(0);
        expect(date.weekDay).to.equal(0);
    });

    it('fastHash', () => {
        const key = Buffer.from('ev5wfjxn8xd0zv2vb61y3hlsbbsfpcjs');
        const result = Util.fastHashBuffer("test", key);
        const result2 = Util.fastHashBuffer("test", key);
        expect(result.toString()).to.equal(result2.toString());


    });
    it('downloadfile', () => {

        Util.downloadFile('https://ferrumgate.com/assets/img/logo.svg', "/tmp/abc.svg");

    });

    it('readFile', async () => {
        const tmp = `/tmp/${Util.randomNumberString()}`;
        fs.writeFileSync(tmp, "hello world\nhello world\n");
        let counter = 0;
        let items: string[] = [];
        await Util.readFileLineByLine(tmp, async (line: string) => {
            counter++;
            items.push(line);
            return true;
        })
        expect(counter).to.equal(2);
        expect(items[0]).to.equal('hello world');

        // windows new line test
        const tmp2 = `/tmp/${Util.randomNumberString()}`;
        fs.writeFileSync(tmp2, "hello world\r\nhello world\r\n");
        counter = 0;
        items = [];
        await Util.readFileLineByLine(tmp2, async (line: string) => {
            counter++;
            items.push(line);
            return true;
        })
        expect(counter).to.equal(2);
        expect(items[0]).to.equal('hello world');

    });

    it('extractTarGz', async () => {
        const tmp = `/tmp/${Util.randomNumberString()}`;
        fs.mkdirSync(tmp);

        const ops = await Util.extractTarGz("./test/data/test.tar.gz", tmp);
        expect(fs.existsSync(`${tmp}/test.txt`)).to.be.true;


    });

    it('listAllFiles', async () => {
        const tmp = `/tmp/${Util.randomNumberString()}`;

        const tmp1 = `${tmp}/${Util.randomNumberString()}`;
        const tmp2 = `${tmp1}/${Util.randomNumberString()}`;
        fs.mkdirSync(tmp2, { recursive: true });
        fs.writeFileSync(`${tmp}/a.txt`, "test");
        fs.writeFileSync(`${tmp1}/b.txt`, "test");
        fs.writeFileSync(`${tmp2}/c.txt`, "test");


        const ops = await Util.listAllFiles(tmp);
        //console.log(ops);
        expect(ops.length).to.equal(3);
    });

    it('mergeAllFiles', async () => {
        const tmp = `/tmp/${Util.randomNumberString()}`;

        const tmp1 = `${tmp}/${Util.randomNumberString()}`;
        const tmp2 = `${tmp1}/${Util.randomNumberString()}`;
        fs.mkdirSync(tmp2, { recursive: true });
        fs.writeFileSync(`${tmp}/a.txt`, "test");
        fs.writeFileSync(`${tmp1}/b.txt`, "test");
        fs.writeFileSync(`${tmp2}/c.txt`, "test");


        const ops = await Util.listAllFiles(tmp);
        ops.sort((a, b) => a.localeCompare(b));
        const dest = `${tmp}/d.txt`;
        await Util.mergeAllFiles(ops, dest);
        expect(fs.existsSync(dest)).to.be.true;

    });







});
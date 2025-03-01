import { decode, encode } from '@msgpack/msgpack';
import Axios from 'axios';
import bcrypt from 'bcrypt';
import ChildProcess from 'child_process';
import crypto, { X509Certificate, createHash } from 'crypto';
import decompress from 'decompress';
import fs from 'fs';
import fsp from 'fs/promises';
import highwayhash from 'highwayhash';
import * as ipAddress from 'ip-address';
import IPCIDR from 'ip-cidr';
import ip6addr from 'ip6addr';
import { BigInteger } from 'jsbn';
import moment from 'moment-timezone';
import nreadlines from 'n-readlines';
import { isIPv4, isIPv6 } from 'net';
import randtoken from 'rand-token';
import dir from 'recursive-readdir';
import { ZipAFolder } from 'zip-a-folder';
import { logger } from './common';
import { TimeZone } from './model/timezone';
import Dns from 'dns/promises';
const decompressTargz = require('decompress-targz');
const decompressUnzip = require('decompress-unzip');
const mergeFiles = require('merge-files');



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


export interface IpRange {
    start: string;
    end: string;
}


export interface NetworkDefinition {
    baseIp: string;
    mask: number;
}


export const Util = {

    /**
     * verify a jwt token with public certificate
     */
    /*verifyJwt: (token: string, key: string) => { //returns token or restfull 401
        try {
            let JWT_VERIFY_OPTIONS = { algorithms: ['RS256'] } as unknown as JWT.VerifyOptions;
            let decoded = JWT.verify(token, key, JWT_VERIFY_OPTIONS) as any;
            let currentTime = new Date().getTime();
            if (decoded.expires <= currentTime) {
                if (process.env.NODE_ENV !== 'development')
                    throw new Error('jwt expired')
            }
            return decoded;

        } catch (err) {
            logger.error(`jwt auth failed with ${token} ${err}`)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'not authorized');
        }
    }, */
    /**
     * create bcyrpt hash of string
     * 
     */
    bcryptHash: (val: string) => {
        return bcrypt.hashSync(val, 10);
    },
    /**
     * compare hash of string to hash
     * @returns true or false
     */
    bcryptCompare: (val: string, hash: string) => {
        return bcrypt.compareSync(val, hash);
    },
    /**
     * creates a random token with len parameters
     */
    createRandomHash: (len: number = 16): string => {
        return randtoken.generate(len);
    },
    /**
     * creates a random string with 6 length
     */
    randomNumberString: (string_length: number = 8) => {


        var chars = "0123456789abcdefghiklmnopqrstuvwxyzABCDEFGHIKLMNOPQRSTUVWXYZ";
        const bytes = crypto.randomBytes(string_length * 2);
        var randomstring = '';
        for (var i = 0; i < string_length; i++) {
            //var rnum = Math.floor(bytes[i] * chars.length);
            randomstring += chars[bytes[i] % chars.length];
        }
        return randomstring;
    },
    replaceNewLine: (val: string) => {
        return val.replace(/(\r\n|\n|\r)/gm, '\\n');
    },
    /**
     * save object to file as json
     * @param obj 
     * @param file 
     */
    saveJson: (obj: any, file: string) => {
        fs.writeFileSync(file, JSON.stringify(obj));
    },
    /**
     * load json from a file
     * @param file 
     */
    loadJson: <T>(file: string): T => {
        return JSON.parse(fs.readFileSync(file).toString()) as T;
    },
    downloadFile: async (url: string, path: string): Promise<void> => {
        const writer = fs.createWriteStream(path);

        const response = await Axios({
            url,
            method: 'GET',
            responseType: 'stream'
        })

        response.data.pipe(writer)

        await new Promise((resolve, reject) => {
            writer.on('finish', resolve)
            writer.on('error', reject)
        })

    },
    extractZipFile: async (path: string, toFolder: string): Promise<string> => {

        //await extract(path, { dir: toFolder });
        await decompress(path, toFolder, {
            plugins: [
                decompressUnzip()
            ]
        })
        return toFolder;
    },
    zipFolder: async (folder: string, topath: string): Promise<void> => {
        await ZipAFolder.zip(folder, topath);
    },
    ipToBigInteger: (ip: string): bigint => {
        if (isIPv4(ip)) {
            let big = new ipAddress.Address4(ip).bigInt();
            return BigInt(big.toString());
        };
        return BigInt(new ipAddress.Address6(ip).bigInt().toString());

    },

    compressIp: (ip: string): string => {
        //ip-address kutuphanesi ipv6 addreslerini compress etmiyordu
        return ip6addr.parse(ip).toString();
    },
    bigIntegerToIp: (ip: bigint): string => {

        if (ip <= BigInt(4294967295))
            return Util.compressIp(ipAddress.Address4.fromBigInt(ip).address);
        else
            return Util.compressIp(ipAddress.Address6.fromBigInt(ip).address);


    },
    ipRangeToCidr: (startIp: string, endIp: string): NetworkDefinition | null => {
        let mask = 32;
        while (mask >= 8) {
            let ip = isIPv4(startIp) ? new ipAddress.Address4(startIp + '/' + mask) : new ipAddress.Address6(startIp + '/' + mask);
            let end = isIPv4(startIp) ? new ipAddress.Address4(endIp + '/' + 32) : new ipAddress.Address6(endIp + '/' + mask);
            if (ip.startAddress().address == startIp && ip.endAddress().address == endIp)
                return { baseIp: startIp, mask: mask };
            mask--;

        }

        return null;
    },

    ipCidrToRange: (ip: string, mask: number): IpRange => {
        let iptemp = isIPv4(ip) ? new ipAddress.Address4(ip + '/' + mask) : new ipAddress.Address6(ip + '/' + mask);
        return { start: Util.compressIp(iptemp.startAddress().address), end: Util.compressIp(iptemp.endAddress().address) }
    },
    isLocalNetwork: (ip: string): boolean => {
        return ip.startsWith('10.') || ip.startsWith('172.16.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('169.254.') || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip == '::1';
    },
    findClientIpAddress: (req: any) => {
        let ip = req.get('x-real-ip');
        if (!ip || ip == 'unknown')
            ip = req.get('client-ip');
        if (!ip || ip == 'unknown')
            ip = req.get('Proxy-Client-IP');
        if (!ip || ip == 'unknown')
            ip = req.get('WL-Proxy-Client-IP');

        if (!ip || ip == 'unknown')
            ip = req.get('HTTP_X_FORWARDED_FOR');

        if (!ip || ip == 'unknown')
            ip = req.get('HTTP_X_FORWARDED');

        if (!ip || ip == 'unknown')
            ip = req.get('HTTP_X_CLUSTER_CLIENT_IP');

        if (!ip || ip == 'unknown')
            ip = req.get('HTTP_CLIENT_IP');

        if (!ip || ip == 'unknown')
            ip = req.get('HTTP_FORWARDED_FOR');

        if (!ip || ip == 'unknown')
            ip = req.get('HTTP_FORWARDED');

        if (!ip || ip == 'unknown')
            ip = req.get('HTTP_VIA');

        if (!ip || ip == 'unknown')
            ip = req.get('REMOTE_ADDR');

        if (!ip || ip == 'unknown')
            ip = req.ip;
        if (!ip || ip == 'unknown')
            ip = req.connection.remoteAddress;
        let parsed = Util.parseIpPort(ip);
        ip = parsed.ip || '0.1.0.1';

        if (ip && ip.substr(0, 7) == "::ffff:") {
            //logger.info(`ip is ipv4 mapped ipv6 ${ip}`);
            ip = ip.substr(7)
        }
        logger.info(`client ip address is ${ip}`);
        return ip;

    },
    parseIpPort(val: string): { ip?: string, port?: number } {
        if (val.includes(']')) {
            let ipTmp = val.substring(0, val.indexOf(']'));
            let portTmp = val.substring(val.indexOf(']') + 1).replace(/[^0-9]/g, '');
            return {
                ip: ipTmp.substring(1),
                port: Number(portTmp) || 1
            }

        }
        if (val.includes('#')) {
            let ipTmp = val.substring(0, val.indexOf('#'));
            let portTmp = val.substring(val.indexOf('#') + 1).replace(/[^0-9]/g, '');
            return {
                ip: ipTmp,
                port: Number(portTmp) || 1
            }
        }
        if (isIPv4(val) || isIPv6(val))
            return {
                ip: val
            }
        return {

        }


    },
    /**
 * @description gets X-Forwarded-Host or host from http headers or returns `not found`
 * @param req http request
 */
    findHttpHost: (req: any): string => {
        //logger.info("http headers:" + JSON.stringify(req.headers))
        return req.get('X-Forwarded-Host') || req.get('host') || 'not found';
    },
    findHttpProtocol: (req: any): string => {
        //logger.info("http headers:" + JSON.stringify(req.headers))
        return req.protocol || 'not found';
    },
    encrypt(key: string, data: string, encoding: BufferEncoding = 'hex'): string {

        const keyBuffer = Buffer.from(key).slice(0, 32); //8f7403c9bb5eb04f

        const iv = Buffer.from("5d97bf41edc9285f0ed88caa9e47218f", 'hex');
        //const pass=crypto.scryptSync(key,initVector,initVector.length);
        const algoritm = 'aes-256-cbc'
        const cipher = crypto.createCipheriv(algoritm, keyBuffer, iv);
        const encrypted = Buffer.concat([cipher.update(Buffer.from(data, 'utf-8')), cipher.final()]);

        return encrypted.toString(encoding);


    },

    decrypt(key: string, data: string, encoding: BufferEncoding = 'hex'): string {

        const keyBuffer = Buffer.from(key).slice(0, 32); //8f7403c9bb5eb04f

        const iv = Buffer.from("5d97bf41edc9285f0ed88caa9e47218f", 'hex');
        //const pass=crypto.scryptSync(key,initVector,initVector.length);
        const algoritm = 'aes-256-cbc'
        const cipher = crypto.createDecipheriv(algoritm, keyBuffer, iv);
        const decrpted = Buffer.concat([cipher.update(Buffer.from(data, encoding)), cipher.final()]);

        let value = decrpted.toString('utf-8');
        return value;


    },

    async sleep(milisecond: number) {
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                resolve('timeout');
            }, milisecond)
        })
    },

    clone<T>(x: T) {
        if (!x) return x;
        return JSON.parse(JSON.stringify(x)) as T;
    },
    /**
     * 
     * @param cmd 
     * @param isStdErr  some programs write output to err, because of redirection usage like openssl, writing to err is nor always error,
     * just follow return code
     * @returns 
     */
    async exec(cmd: string, isStdErr = true) {
        return new Promise((resolve, reject) => {
            ChildProcess.exec(cmd, (error, stdout, stderr) => {
                if (error)
                    reject(error);
                else
                    if (stderr && isStdErr)
                        reject(stderr);
                    else
                        if (stdout)
                            resolve(stdout);
                        else
                            resolve('');

            })
        })
    },
    async spawn(cmd: string, args?: string[], throwError = true, redirectErr = false) {

        return new Promise((resolve, reject) => {

            let buf = Buffer.from([]);
            const process = ChildProcess.spawn(cmd, args);
            process.on('exit', (code) => {
                if (code && throwError)
                    reject(buf.toString('utf-8'));
                else {

                    resolve(buf.toString('utf-8'));
                }
            })
            process.stdout.on('data', (data: Buffer) => {
                buf = Buffer.concat([buf, data]);
            })
            process.stderr.on('data', (data: Buffer) => {
                if (!redirectErr)
                    buf = Buffer.concat([buf, data]);
            })
            process.on('error', (err) => {
                reject(err);
            })


        })
    },


    async createSelfSignedCrt(domain: string, days = '3650', folder?: string) {
        //openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout ${domain}.key -out ${domain}.crt -subj "/CN=${domain}/O=${domain}"
        const tmpFolder = folder || `/tmp/${Util.randomNumberString(16)}`;
        if (!fs.existsSync(tmpFolder))
            await fsp.mkdir(tmpFolder, { recursive: true });
        await this.exec(`openssl req -x509 -nodes -days ${days} -newkey rsa:2048 -keyout ${tmpFolder}/${domain}.key -out ${tmpFolder}/${domain}.crt -subj "/CN=${domain}/O=${domain}"`, false);
        let val = { privateKey: await fsp.readFile(`${tmpFolder}/${domain}.key`, 'utf-8'), publicCrt: await fsp.readFile(`${tmpFolder}/${domain}.crt`, 'utf-8') }
        if (!folder) {
            await fsp.rm(tmpFolder, { force: true, recursive: true });
        }
        return val;
    },
    async createCASignedCrt(domain: string, org: string, cerficate: { privateKey: string, publicCrt: string }, days = '3650', folder?: string) {
        const tmpFolder = folder || `/tmp/${Util.randomNumberString(16)}`;
        if (!fs.existsSync(tmpFolder))
            await fsp.mkdir(tmpFolder, { recursive: true });
        await fsp.writeFile(`${tmpFolder}/ca.key`, cerficate.privateKey, 'utf-8');
        await fsp.writeFile(`${tmpFolder}/ca.crt`, cerficate.publicCrt, 'utf-8');
        await this.exec(`openssl req -nodes -days ${days} -newkey rsa:2048 -keyout ${tmpFolder}/${domain}.key -out ${tmpFolder}/${domain}.csr -subj "/CN=${domain}/O=${org}"`, false);
        await this.exec(`openssl x509 -req -CA ${tmpFolder}/ca.crt -CAkey ${tmpFolder}/ca.key -CAcreateserial -days ${days} -in ${tmpFolder}/${domain}.csr -out ${tmpFolder}/${domain}.crt`, false);
        let ret = { privateKey: await fsp.readFile(`${tmpFolder}/${domain}.key`, 'utf-8'), publicCrt: await fsp.readFile(`${tmpFolder}/${domain}.crt`, 'utf-8') }
        if (!folder) {
            await fsp.rm(tmpFolder, { force: true, recursive: true });
        }
        return ret;
    },
    async getCertificateInfo(crt: string, ca: string) {
        const getDaysBetween = (validFrom: any, validTo: any) => {
            return Math.round(Math.abs(+validFrom - +validTo) / 8.64e7);
        };

        const getDaysRemaining = (validTo: any) => {

            return new Date(validTo).getTime() - new Date().getTime();

        };

        const x509 = new X509Certificate(Buffer.from(crt));
        const cax509 = new X509Certificate(Buffer.from(ca));
        const isValid = x509.verify(cax509.publicKey);

        return { isValid: isValid, remainingMS: getDaysRemaining(x509.validTo), issuer: x509.issuer, subject: x509.subject, validFrom: x509.validFrom, validTo: x509.validTo }

    },

    /**
     * @summary source array at least 1 element exits in target array
     */
    isArrayElementExist(source?: any[], target?: any[]) {
        if (!Array.isArray(source)) return false;
        if (!Array.isArray(target)) return false;
        const item = source?.find(x => target?.includes(x))
        return Boolean(item);
    },
    isArrayEqual(source?: any[], target?: any[]) {
        if (this.isUndefinedOrNull(source) && this.isUndefinedOrNull(target)) return true;
        if (!this.isUndefinedOrNull(source) && this.isUndefinedOrNull(target)) return false;
        if (this.isUndefinedOrNull(source) && !this.isUndefinedOrNull(target)) return false;
        const sFind = source?.find(x => !target?.includes(x))
        if (sFind) return false;
        const tFind = target?.find(x => !source?.includes(x));
        if (tFind) return false;
        return true;

    },
    isUndefinedOrNull(val?: any) {
        if (val === undefined) return true;
        if (val === null) return true;
        return false;

    },
    convertToBoolean(val?: any) {
        if (this.isUndefinedOrNull(val)) return false;
        if (typeof (val) == 'string') return val == 'true';
        if (typeof (val) == 'number') return Boolean(val).valueOf();
        if (typeof (val) == 'boolean') return val;
        if (Array.isArray(val)) return true;
        if (typeof (val) == 'object') return true;
        return false;

    },
    convertToArray(val?: string, splitter = ','): string[] {
        if (!val) return [];
        return val.split(splitter).filter(x => x);
    },
    /**
     * @summary always returns a number at least 0 returns
     * @param val 
     * @returns 
     */
    convertToNumber(val?: string | number): number {
        if (!val) return 0;
        const n = Number(val)
        if (Number.isNaN(n)) return 0;
        return n;
    },


    maskFields(val: any, fields: string[] = []) {
        if (val == undefined) return val;
        if (val == null) return val;
        if (typeof (val) == 'string') {
            if (val)
                return Util.randomNumberString(16);
            return val;
        }
        if (typeof (val) == 'number')
            return 0;
        if (Array.isArray(val)) {
            val = val.map(x => {
                return this.maskFields(x, fields);
            });
            return val;
        }
        if (typeof (val) == 'object') {
            Object.keys(val).forEach(x => {
                if (!fields.includes(x)) {
                    val[x] = Util.maskFields(val[x], fields);
                }
            })
        }
        return val;
    },

    any(val: any) {
        if (val == null) return null;
        if (val == undefined) return undefined;
        return val as any;
    },
    nanosecond() {
        const NS_PER_SEC = 1e9;
        const [second, nanosecond] = process.hrtime();
        return second * NS_PER_SEC + nanosecond;
    },
    milisecond() {
        const NS_PER_SEC = 1e9;
        const [second, nanosecond] = process.hrtime();
        return (second * NS_PER_SEC + nanosecond) / 1000000;
    },
    milisecondInt() {
        const NS_PER_SEC = 1e9;
        const [second, nanosecond] = process.hrtime();
        return Math.trunc((second * NS_PER_SEC + nanosecond) / 1000000);
    },
    now() {
        return new Date().getTime();
    },
    jencode(val: any) {
        if (process.env.JENCODE == 'json')
            return Buffer.from(JSON.stringify(val));
        else
            return Buffer.from(encode(val))
    },
    jdecode(val: Buffer) {
        if (process.env.JENCODE == 'json')
            return JSON.parse(val.toString());
        else
            return decode(val);
    },
    jencrypt(key: string, data: string | Buffer): Buffer {

        const keyBuffer = Buffer.from(key).subarray(0, 32); //8f7403c9bb5eb04f

        const iv = Buffer.from("5d97bf41edc9285f0ed88caa9e47218f", 'hex');
        //const pass=crypto.scryptSync(key,initVector,initVector.length);
        const algoritm = 'aes-256-cbc'
        const cipher = crypto.createCipheriv(algoritm, keyBuffer, iv);
        const buf = typeof (data) == 'string' ? Buffer.from(data, 'utf-8') : data;
        const encrypted = Buffer.concat([cipher.update(buf), cipher.final()]);

        return encrypted;


    },
    jdecrypt(key: string, data: string | Buffer): Buffer {

        const keyBuffer = Buffer.from(key).subarray(0, 32); //8f7403c9bb5eb04f

        const iv = Buffer.from("5d97bf41edc9285f0ed88caa9e47218f", 'hex');
        //const pass=crypto.scryptSync(key,initVector,initVector.length);
        const algoritm = 'aes-256-cbc'
        const cipher = crypto.createDecipheriv(algoritm, keyBuffer, iv);
        const buf = typeof (data) == 'string' ? Buffer.from(data, 'utf-8') : data;
        const decrpted = Buffer.concat([cipher.update(buf), cipher.final()]);

        return decrpted;
    },
    ipToHex(ip: string) {
        let arr = [];
        if (isIPv4(ip)) {
            const xx = new ipAddress.Address4(ip)
            arr = xx.toArray();
            arr.unshift(...[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        }
        else {
            const yy = new ipAddress.Address6(ip);
            arr = yy.toByteArray();
        }

        var s = '0x';
        arr.forEach((byte) => {
            s += ('0' + (byte & 0xFF).toString(16)).slice(-2);
        });
        return s;
    },
    cidrNormalize(ipRange: string) {
        const cidr = new IPCIDR(ipRange);
        const str = cidr.addressStart.correctForm() + cidr.addressStart.subnet;
        return str;
    },
    timeZoneList(): TimeZone[] {

        let zones: TimeZone[] = [];
        const zonenames = moment.tz.names();
        for (const zone of zonenames) {
            const tz = moment.tz.zone(zone);
            if (tz) {
                zones.push({ name: tz.name, offset: tz.parse(new Date().getTime()) });
            }
        }
        return zones;
    },
    timeInZone(zone: string, time?: number) {
        let z = moment.tz(time ? new Date(time) : Date.now(), zone);
        return {
            hour: z.hour(),
            minute: z.minute(),
            second: z.second(),
            milisecond: z.millisecond(),
            weekDay: z.day()
        }
    },
    deleteUndefinedProps(obj: any) {
        Object.keys(obj).forEach(x => {
            if (obj[x] == undefined)
                delete obj[x];
        })
        return obj;
    },


    fastHashLow(s: string, random: Buffer): number {

        return highwayhash.asUInt32Low(random, Buffer.from(s));

    },
    fastHashHigh(s: string, random: Buffer): number {

        return highwayhash.asUInt32Low(random, Buffer.from(s));

    },
    fastHashBuffer(s: string, random: Buffer): Buffer {

        return highwayhash.asBuffer(random, Buffer.from(s));

    },
    fastHashString(s: string, random: Buffer): string {

        return highwayhash.asString(random, Buffer.from(s));

    },
    readFileLineByLine: async (filename: string, callback: (line: string) => Promise<boolean>) => {

        const liner = new nreadlines(filename);
        let line: Buffer | null | false = null;
        while (line = liner.next()) {
            try {
                if (line.at(line.byteLength - 1) == 0x0d) {
                    line = line.subarray(0, line.byteLength - 1);
                }
                const result = await callback(line.toString('utf-8').trim());
                if (!result) break;
            } catch (ignore) {
                console.log(ignore);
                break;
            }
        }

    },
    extractTarGz: async (filename: string, destFolder: string) => {
        return await decompress(filename, destFolder, {
            plugins: [
                decompressTargz()
            ]
        })
    },
    listAllFiles: async (folder: string) => {
        return await dir(folder);
    },
    mergeAllFiles: async (files: string[], dest: string) => {
        return await mergeFiles(files, dest);
    },
    randomBetween(min: number, max: number) {
        return Math.floor(
            Math.random() * (max - min) + min
        )
    },
    sha256(content: string) {
        return createHash('sha256').update(content).digest('base64')
    },
    resolveHostname: async (hostname: string) => {
        if (!hostname) return null;
        if (isIPv4(hostname) || isIPv6(hostname))
            return hostname;
        let records = await Dns.resolve(hostname);
        return records.length > 0 ? records[0] : null;
    },
    splitCertFile(file: string): string[] {

        let finalList: string[] = [];
        if (!file) return finalList;
        const lines = file.split('\n')
        let tmp: string[] = [];
        let findedStartPoint = false;
        for (const l of lines) {
            if (l.startsWith('-----BEGIN CERTIFICATE-----')) {
                findedStartPoint = true;
                tmp.push(l);
            } else
                if (findedStartPoint && l.startsWith('-----END CERTIFICATE-----')) {
                    findedStartPoint = false;
                    tmp.push(l + '\n');

                    finalList.push(tmp.join('\n'));
                    tmp = [];
                } else if (findedStartPoint) {
                    tmp.push(l);
                }
        }
        return finalList

    },
    extractDomainFrom(url: string) {
        const regex = /(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/?\n]+)/g;
        const match = regex.exec(url);
        let domain = match ? match[1] : null;
        if (!domain) return null;
        return domain.split('.').splice(-2).join('.');
    }


}


